---
title: "An introduction to Browser Exploitation Part 1: Overview"
date: 2026-01-31 00:00:00 +0800
categories: [Browser Exploitation]
tags: [Introduction, Browser Exploitation]
---
## Introduction
Welcome, this is my first blog post on this concept. We'll explore the basics of browsers and then dive into the complex world of browser exploitation.
## Browser Overview and Components
### Browser Overview
Web browsers are among the most essential and widely used software applications that people interact with. Today, almost every device that connects to the internet uses a browser-engine to transform remote data into a human-friendly format (webpages). There are an estimated 3+ billion devices with browsers active monthly.

This is a snapshot of a browser usage table. Chrome accounts for roughly 60% of users, Safari roughly 17%. [https://caniuse.com/usage-table](https://caniuse.com/usage-table)

![](browser_overview.png)
Simultaneously, web browsers are among the largest and most complex pieces of software ever created. This makes intuitive sense, as in many cases, these projects have grown alongside web technologies or even pioneered them. JavaScript itself, today an underpinning of the modern tech ecosystem, was invented as a dynamic feature for NetScape Navigator in the early 90's.

These are enormous pieces of software that contain incalculable complexity. In fact, browsers can rival the operating systems they run on in many cases:
![](compare.png)
While the scale may be intimidating, this degree of complexity is a double-edged sword as it guarantees the inescapable fate of exploitable bugs and flaws
### Browser Components
Although we commonly think of a web browser as a single, monolithic entity, it is often more appropriate to think about them as a collection of layered components:
![](component.png)
Each browser will differ in its specific implementation, but this general architecture provides a useful mental model for thinking about browsers at a technical level.

When users interact with a web browser, they will typically see something like this:
![](example1.png)
We can see all the familiar bits and pieces of a modern desktop browser:

- URL Bar
- Various Tabs
- Bookmarks
- Website Content
- etc...

We can already draw an important distinction between two major browser subsystems:

- The "broker" which handles the frontend UI and interactions between the address bar, bookmarks, tabs, and other parts of the native browser application.
- The "renderer" which handles everything related to displaying the actual web content: parsing html, applying css styles, running JavaScript, etc.

![](example2.png)

## Browser Processes
The 'native browser' and 'renderer' define both a subsystem separation as well as a security boundary. This begs the question of how this security boundary is enforced or implemented; as both of these components seem to exist within a single program.

The most common modern approach is to create a hard separation by placing dangerous components (such as the renderer) into their own process. We can see this with Task Manager quite easily:
![](task.png)
Despite only running a single instance of Chrome, we can clearly see more than just "one" `chrome.exe` process running. Each of these processes contains an isolated component of the overall browser.

On Linux, we can more easily see a hierarchy emerge using `ps fx`:
```
itszn  87743  /bin/bash
itszn  87746   \_ /usr/lib/chromium-browser/chromium-browser --enable-pinch
itszn  87754       \_ /usr/lib/chromium-browser/chromium-browser --type=zygote
itszn  87756       |   \_ /usr/lib/chromium-browser/chromium-browser --type=zygote
itszn  87837       |       \_ /usr/lib/chromium-browser/chromium-browser --type=renderer 
itszn  87878       |       \_ /usr/lib/chromium-browser/chromium-browser --type=renderer 
itszn  87889       |       \_ /usr/lib/chromium-browser/chromium-browser --type=renderer 
itszn  87966       |       \_ /usr/lib/chromium-browser/chromium-browser --type=renderer 
itszn  87985       |       \_ /usr/lib/chromium-browser/chromium-browser --type=renderer 
itszn  88019       |       \_ /usr/lib/chromium-browser/chromium-browser --type=utility
itszn  87778       \_ /usr/lib/chromium-browser/chromium-browser --type=gpu-process
itszn  87836           \_ /usr/lib/chromium-browser/chromium-browser --type=-broker
```
We can immediately pull out a few different "process types" that make up Chrome:

- zygote
- renderer
- broker
- utility
- gpu-process

Most notably, the majority of these processes are of `type=renderer`. This makes intuitive sense: the renderer is responsible for displaying and handling (nearly) all web-content. It is sometimes also referred to as the "Content Process" for this reason.

Furthermore, this implies that a new renderer is required for each webpage, browser tab, iframe, etc. Placing this untrusted content in a separate process increases the overall stability of the browser as well: If any bugs are triggered, only one browser-tab crashes rather than the entire browser. You've likely seen this in action if you've ever seen one of the infamous "Oops, something went wrong!" screens in Chrome.

## General Browser Architecture

Now that we've broken the browser down into a few logical components and have taken a quick look at how they use processes to compartmentalize complexity, we can draw a diagram that is more faithful to the technical reality of modern web browsers:
![](gba1.png)
![](gba2.png)
This time, we can also see the major parts that make up the renderer. The components shown are essentially self-explanatory in their purpose, but as we can see, they each break into additional sub-components that achieve specific goals.

However, as we see complexity exploding every time we peel away another layer, it begs the question of how multiple browser vendors all coordinate to provide a consistent experience. It would be an unimaginable mess if `let a = 1 + b * 0` had different order-of-operations rules applied on Chrome versus Safari.

### Web Standards and Specifications

This problem is generally solved by following various web standards and specifications. Nearly each "sub-box" that we drew into our diagram has a large, exhaustive document associated with it that describes the exact behavior browsers are expected to implement. By adhering to this common set of standards, the vendors can all be confident in their compatibility.

As you may imagine, there are many standards to abide by. Some of the noteworthy ones:

W3C - [HTML related standards](https://www.w3.org/TR/?tag=html), [CSS](https://www.w3.org/TR/?tag=css)

WHATWG - [HTML](https://html.spec.whatwg.org/multipage), [DOM](https://dom.spec.whatwg.org/), [Fetch](https://fetch.spec.whatwg.org/), [URL](https://url.spec.whatwg.org/), etc

ECMA - [JavaScript standards](https://www.ecma-international.org/ecma-262/9.0/index.html#Title)

Although many of these documents are far too dense to be useful "most of the time", it is important to be aware of their existence. Vulnerabilities often hide in the edge cases, and if you ever need the "ground truth" on how something is **supposed to** be implemented, the standards are where you will find that information.

### WebIDL: Web Interface Definition Language

A particularly important specification to be familiar with is the [Web Interface Definition Language](https://webidl.spec.whatwg.org/)

WebIDL provides a standardized way to define APIs between various browser components. Conceptually, you can think of it as a blueprint for the "glue" that allows the components we've seen to interface with each other. During the build process, WebIDLs are automatically converted into C++ code and other components can include the resulting header files to interface with a particular component.

Below is a snippet of an example WebIDL file:
```
[Constructor,
 Exposed=Window]
interface Document : Node {
  [SameObject] readonly attribute DOMImplementation implementation;
  readonly attribute USVString URL;
  readonly attribute USVString documentURI;
  readonly attribute USVString origin;
  readonly attribute DOMString compatMode;
  readonly attribute DOMString characterSet;
  readonly attribute DOMString charset; // historical alias of .characterSet
  readonly attribute DOMString inputEncoding; // historical alias of .characterSet
  readonly attribute DOMString contentType;

  readonly attribute DocumentType? doctype;
  readonly attribute Element? documentElement;
  HTMLCollection getElementsByTagName(DOMString qualifiedName);
  HTMLCollection getElementsByTagNameNS(DOMString? namespace, DOMString localName);
  HTMLCollection getElementsByClassName(DOMString classNames);
  ...
  ```
  Both Chrome and Safari use WebIDLs.