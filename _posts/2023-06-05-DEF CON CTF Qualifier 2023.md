---
layout:     post
title:      DEFCON CTF Qualifier
subtitle:   2023
date:       2023-06-05
author:     lyk
header-img: img/post-bg-cook.jpg
catalog: true
tags:
    - Writeup
---

# Raw Water

sqlite sql注入

它的表单要填的有点多

上jio本

```js
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
document.querySelector('input').value = "'|| sqlite_version() || '";
for (;;) {
  [...document.querySelectorAll("input")].forEach(
    (i) => (i.value ||= "1")
  );
  document.querySelector("main > form > button").click();
  await wait(500);
  if (new URL(location.href).pathname.startsWith("/orders/")) {
    break;
  }
}
```



# Artifact Bunker

A web interface and something with uploading zips! 
After long hours of waiting, `artifact bunker` finally presents the first web-challenge in the defcon qualifiers! So let's dive straight in and see what this thing does.
[Link to challenge](https://github.com/Nautilus-Institute/quals-2023/tree/main/artifact-bunker) (with Dockerfile!) 

### 0x01 Exploration

We get website with some doomsday-paranoid advertising for storing your CI / CD artifacts in a super-secure bunker. 
We interact with the application through what looks like a military-grade rugged computer terminal with shitty control buttons.
We can upload `zip` or `tar` archives by drag'n'dropping them into the screen and then we can browse the uploaded archives and see the contents of the contained files.
We can also hit a mysterious `prep-artifacts` button that will make a `app-main--<timestamp>` archive appear, containing some weird text files.

So far so ... good? Let's look at the code! HTTP requests are so web2, of course in a defcon challenge, everything happens with websockets!
Once you open the site, a websocket connection is established to provide the actual functionality. 
The back-end server is written in go-lang and handles - among others - the following websocket events/commands:

#### `upload` 

As the name suggests, this command allows us to upload archives, some important observations:

- Your file name must end with `.zip` or `.tar`.
- You can not "overwrite" an archive with the same name.
- Your archive will be opened by the server and its members stored into a zip archive **with the extension stripped** 
- All uploaded archives get "censored" in the `compress_files` function. 
  Meaning if an archive members name contains certain words, it is dropped and the file contents are scanned for certain regex patterns which are replaced with `***`. The words and patterns are specified in the config file.

#### `download` 

So say you uploaded `my-archive.(tar|zip)`, you can then download members from your archive by passing `my-archive/my-member` to the `download` command. (Note the lack of extension!) 
To accomplish this "feature" the server will open the **zip** archive created in the upload step. 


#### `job` (packaging) 

The third important command is the `job` command, which only supports one subcommand: `package`. 
You can also pass an arbitrary `name` for the package-job.
Under the hood, this feature is massively over-engineered:
In the spirit of CI-Tools the actual input is a yaml file that describes `steps` (archives) of a certain `name` that contain certain files.
The go server will prepare that yaml by applying some variables to a template file (included in the source) with go-langs templating engine which is similar to jinja or django templating for the web folks reading this. For every `step` it will create a `.tar` archive and again a zip archive **without** an extension.

Did you catch it? It creates archives with a `name` and we can specify a `name` for our websocket command...

#### It's an InYection

So we control the `name` variable and the template for the CI job looks like this:

```yaml
job:
  steps:
    - use: archive
      name: "{{.Name}}-{{.Commit}}-{{.Timestamp}}"
      artifacts:
        - "bunker-expansion-plan.txt"
        - "new-layer-blueprint.txt"
```

With our specially crafted `name` it turns into this:
![Inected YAML](..\img\InYection.png)

One big limitation we have here, is that we can only include "artifacts" that are inside the `/project` directory. This is again specified in the config file via the `root` setting. 
The good news is that `flag.txt` is in this `/project` directory and that the CI job will create a `.tar` archive and a zip archive in the `/data` directory.
Note that `.tar` doesn't have any compression.
The bad news is that the zip archive will be created with `compress_files`, which applies the "censorship" mechanism described earlier. 
And you might remember that the download command will always and only look at zip archives.

So we have a mechanism to get the plaintext flag into a tar file in `/data`, but how do we get it out of there?

### 0x02 There is an overwrite

We spent a lot of time pocking around for path traversals in the archive processing logic, because after all: This is a web-challenge, right? RIGHT?

We didn't find anything like that, but suddenly we discovered that the loathed `compress_files` function did have a bug: 

It doesn't check whether the file it was writing the archive to already exists! So it would overwrite existing files. 
Notice that it will _overwrite_ not _replace_: If the preexisting file is larger than the new zip file, the "bottom" contents of 
the original will not be erased! Additionally, we can use this to write into the tar created by the InYection by using 
`filename.tar.zip` as the filename, since only the `.zip` extension will be stripped!

So now it became clearer what we had to do: 

1. Create a large tar with the flag inside using our InYection
2. Use the overwrite to write zip metadata into the tar archive
3. Read the flag from zip/tar with the download function

Our thought process was of course a lot less straight forward than that during the CTF. But to spare you the pain, we 
will now give you a short intro into the zip archive format:

### 0x03 Zip Intro title I guess

So here it is, the part of the writeup you have all been waiting for: a lengthy introduction of which you will skip half, just to later read all of it again because you did not understand the exploit.<br>
During the CTF, we used [this documentation](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html) for details about the Zip archive structure, which already leaves out a lot of details that were not relevant for the challenge.

The general Zip structure looks like this:<br>

![Image](..\img\general-zip-structure.png "General Zip file structure")

[Source](https://www.codeproject.com/KB/cs/remotezip/diagram1.png)

A directory of all files, called _Central Directory_ (CD) is placed at the end (yes you read that right) of a ZIP file. This identifies what files are in the Zip and where there are located (it doesn't literally need to be at the end, but we'll come back to this later).<br>
The CD consists of a _CD File Header_ for each file in the archive, that contains multiple fields, among them:

- `file-name-len` and `file-name`: Name of a member: *Uncompressed and arbitrary*, max 2^16 bytes 
- `compression`: May also be "no compression" (`0`)
- `crc-32`: if this is `0`, the checksum is ignored
- `compressed-size`
- `extra-filed-length`: extra data after the `file-name`, max 2^16 bytes
- `offset`: This is not the offset of the file content itself: the content is preceded by a _Local File Header_, which simply repeats most of the details already present in the central directory.

As mentioned above, the Zip archive does not need to end in the CD. The standard allows for a _File comment_ of length up to 65535 bytes after the CD, which can contain arbitrary data.
(Flags for example).



### 0x06 Fix(es):

As usual, the yaml injection could be fixed by properly sanitizing/validating user inputs. While theoretically 
linux allows lots of unusual characters in file names, this use-case requires that at least quotes and newlines are 
escaped. An allow-list of characters might be even more adequate.

`compress_files` overwriting files is obvious bug that should be fixed by either completely replacing existing files
or aborting if the file already exists. 

To avoid the collision of file-names that allowed us to target `manyflgs.tar` with `compress_files`, file-name handling should be implemented more prudently. It currently overlooks at least one corner case: files with multiple "extensions". One simple fix might be using separate directories for `zip` and `tar` files.
