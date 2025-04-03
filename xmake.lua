set_project("udpfwd")

target("udpfwd")
    set_kind("binary")
    add_files("src/*.c")
    add_cflags("-Wall", "-Wpedantic")
    if is_os("windows") then
        add_links("ws2_32")
    end
