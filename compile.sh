if [ $# -lt 1 ]; then
    echo "usage: $0 make user_program_path user_program_parameters"
    echo "	 $0 clean to clean the complied files"
    echo "	 $0 example to complie the example program"
    exit 1
fi

first_param="$1"


if [ "$first_param" = "make" ]; then
    shift
    total_length=0

    for param in "$@"; do
        param_length=${#param}+1
        total_length=$((total_length + param_length))
    done
    if [ -e .parameters ]; then
        rm .parameters
    fi
    touch .parameters
    echo "#define ARGC $#" >> .parameters
    echo "#define ARGV_LEN $total_length" >> .parameters
    echo -n '#define PARAMETERS "' >> .parameters
    
    
    for param in "$@"; do
        echo -n "$param\0" >> .parameters
    done

    echo -n '"' >> .parameters

    make clean
    make
    cp ./hypervisor/hypervisor.elf .
    cp ./kernel/kernel.bin .
    cd ./shim-kvm
    cargo build --target=x86_64-unknown-none --out-dir ../ -Z unstable-options
    echo "make finished, usage: ./hypervisor.elf ./enarx-shim-kvm ./kernel.bin"
    
elif [ "$first_param" = "clean" ]; then
    if [ -e .parameters ]; then
        rm .parameters
    fi
    touch .parameters
    echo "#define ARGC 0" >> .parameters
    echo "#define ARGV_LEN 0" >> .parameters
    echo '#define PARAMETERS ""' >> .parameters
    rm ./hypervisor.elf
    rm ./kernel_example.bin
    make clean
    echo "clean finished"
    
elif [ "$first_param" = "example" ]; then
    ./compile.sh make ./orw.elf /etc/os-release
    echo "example compiled"
    
else
    echo "invalid: $first_param"
fi
