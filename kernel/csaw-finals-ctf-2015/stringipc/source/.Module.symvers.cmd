cmd_/home/peilin/ctf/kernel/csaw-finals-ctf-2015/stringipc/source/Module.symvers := sed 's/ko$$/o/' /home/peilin/ctf/kernel/csaw-finals-ctf-2015/stringipc/source/modules.order | scripts/mod/modpost -m -a   -o /home/peilin/ctf/kernel/csaw-finals-ctf-2015/stringipc/source/Module.symvers -e -i Module.symvers  -N -T -
