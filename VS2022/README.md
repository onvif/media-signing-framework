### Environment variables

To build this solution, you need:
- OpenSSL 3.3.1 x64 or higher
- GStreamer x64 dev version

Also, you should add two Environment variables to tell where those components are installed: 
- OPENSSL_PATH
- GSTREAMER

As exmaple:
- OPENSSL_PATH = C:\Program Files\OpenSSL-Win64
- GSTREAMER = C:\gstreamer\1.0\msvc_x86_64

Otherwise, please update project properties yourself, depending on used libraries and paths.