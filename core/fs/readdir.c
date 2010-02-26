#include <stdio.h>
#include <string.h>
#include <sys/dirent.h>
#include "fs.h"
#include "core.h"

/* 
 * open dir, return the file structure pointer in _eax_, or NULL if failed 
 */
void opendir(com32sys_t *regs)
{
    const char *src = MK_PTR(regs->es, regs->esi.w[0]);
    struct file *file;
    int rv;

    rv = searchdir(src);
    if (rv < 0) {
	regs->eax.l = 0;
	regs->eflags.l |= EFLAGS_ZF;
    } else {
	regs->eax.l = (uint32_t)handle_to_file(rv);
	regs->eflags.l &= ~EFLAGS_ZF;
    }
}

/*
 * Read one dirent at one time. 
 *
 * @input: _esi_ register stores the address of DIR structure
 * @output: _eax_ register stores the address of newly read dirent structure
 */
void readdir(com32sys_t *regs)
{
    DIR *dir = (DIR *)regs->esi.l;	
    struct dirent *de = NULL;
    
    if (dir->dd_dir)
	de = this_fs->fs_ops->readdir(dir->dd_dir);
    else
	de = NULL;
    
    /* Return the newly read de in _eax_ register */
    regs->eax.l = (uint32_t)de;
}

void closedir(com32sys_t *regs)
{
    DIR *dir = (DIR *)regs->esi.l;
    _close_file(dir->dd_dir);
}

