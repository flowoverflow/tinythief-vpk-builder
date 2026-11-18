# Tiny Thief for PS Vita

An unofficial **Tiny Thief PS Vita port**, with an easy browser-based builder that
turns your own Android game files into a VPK you can install on your Vita.

**The original Tiny Thief game is not included in this repository.** No XAPK, APK,
OBB game archive, original game libraries, or original artwork is provided. You
must supply your own **Tiny Thief 1.2.1 XAPK** to create the playable VPK.

## What you'll need

- Your own **Tiny Thief 1.2.1 `.xapk` file — NOT an `.apk` file**.
- A current desktop web browser.
- A PS Vita set up for homebrew, with VitaShell, kubridge, and
  `ur0:data/libshacccg.suprx` installed.

## Build your PS Vita VPK

1. **Open the GitHub Pages builder.** Use the **`github.io` website associated
   with this repository**, available through the repository's website link.
   The builder runs directly in your browser.

2. **Choose your XAPK — NOT an APK.** Drag your Tiny Thief 1.2.1 **`.xapk`** onto
   the page, or click the file area to select it. An XAPK contains both the Android
   app and its game data. **An `.apk` alone will not work**, and renaming an APK
   to `.xapk` will not convert it. Wait for the builder to check your file.

3. **Review the LiveArea artwork and startup images.** Check the bubble icon,
   LiveArea background, start button, boot picture, and startup picture. Use
   **View** to see an image at full size. You can keep the generated artwork or
   click a picture to replace it with your own.

4. **Build the VPK.** When you're happy with the artwork, click **Build the VPK**.

5. **Download your VPK.** Click **Save TinyThief.vpk** to save the finished file
   to your computer.

6. **Install it on your PS Vita.** Transfer `TinyThief.vpk` to your Vita, open it
   in **VitaShell**, and install it. Then launch Tiny Thief from its home-screen
   bubble.

## Your files stay on your computer

Choosing or dropping your XAPK on the website does **not** upload it to a server.
The game files are processed locally in your browser, and the finished VPK is
downloaded directly to your computer. The builder creates the artwork from your
own game files unless you choose replacement images.
