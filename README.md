# ffmpjpeg-httpd

Example:
```
$ ffmpeg -hide_banner -nostats \
  -vaapi_device /dev/dri/renderD128 -f v4l2 -standard PAL -i /dev/video0 \
  -vf 'format=nv12,hwupload,deinterlace_vaapi=rate=frame:auto=1' -c:v mjpeg_vaapi -global_quality 90 \
  -f mpjpeg - | ffmpjpeg-httpd --addr 127.0.0.1 --port 8080 --skip 4
```
