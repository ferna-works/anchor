check:
    shellcheck {{ justfile_dir() }}/scripts/*.sh
    shfmt -d -i 2 -ci {{ justfile_dir() }}/scripts/*.sh

fmt:
    shfmt -w -i 2 -ci {{ justfile_dir() }}/scripts/*.sh
