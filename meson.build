project('pipewire_kinect_source', 'c')

pipewiredeps = [dependency('libpipewire-0.3'), dependency('libspa-0.2')]
freenectdeps = dependency('libfreenect')
pthreaddeps = dependency('threads')

module_sources = [
  'source.c',
  ]

pipewire_module_kinect_source = shared_library('pipewire-module-kinect-source',
  [ 'source.c' ],
  dependencies : [pipewiredeps, freenectdeps, pthreaddeps],
  install : true,
  install_dir : '/usr/lib/pipewire-0.3'
  )
