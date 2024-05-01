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
