def argfd(child, fd):
  child_fd = child.inherit_fd(fd)
  child_fd.fcntl(F_SETFD, 0) # unset CLOEXEC
  return str(int(child_fd))

audio_pipe = local.pipe()
video_pipe = local.pipe()
source = local.clone()
source.execv('/bin/source', ['source',
  '--audio-out', argfd(source, audio_pipe.write),
  '--video-out', argfd(source, video_pipe.write)])
video_sink = local.clone()
video_sink.execv('/bin/video_sink', ['video_sink',
  '--video-in', argfd(video_sink, video_pipe.read)])
audio_sink = local.clone()
audio_sink.execv('/bin/audio_sink', ['audio_sink',
  '--audio-in', argfd(audio_sink, audio_pipe.read)])
