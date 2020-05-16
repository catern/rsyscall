def as_argument(fd):
    fcntl(fd, F_SETFD, 0) # unset CLOEXEC
    return str(int(fd)) # turn fd number to string

audio_pipe = local.pipe()
video_pipe = local.pipe()
source_pid = os.fork()
if source_pid == 0:
    try:
        os.execv('/bin/source', ['source',
          '--audio-output', as_argument(audio_pipe.write),
          '--video-output', as_argument(video_pipe.write)])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
video_sink_pid = os.fork()
if video_sink_pid == 0:
    try:
        os.execv('/bin/video_sink', ['video_sink',
          '--video-input', as_argument(video_sink, video_pipe.read)])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
audio_sink_pid = os.fork()
if audio_sink_pid == 0:
    try:
        os.execv('/bin/audio_sink', ['audio_sink',
          '--audio-input', as_argument(audio_sink, audio_pipe.read)])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
