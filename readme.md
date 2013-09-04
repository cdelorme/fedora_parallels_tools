
# Patching Parallels Tools

I am not a C specialist, so what I have done is peice together a working copy, I have no idea whether this is "ideal".  However, not having parallels tools means, generally, worse performance.  Sadly the makers of the fabulous Parallels Desktop project drag their feet when it comes to linux distributions.

Running quickly over the basic steps:

    mkdir -p /media/cdrom
    mount /dev/sr0 /media/cdrom
    cp -R /media/cdrom /root/
    cd /root/cdrom

Once inside here you may either copy the `prl_mod.tar.gz` file inside the kmods folder OR replace it with the copy included with this readme.


---

The first set of bugs are in the `prl_tg` component, so that's where I started.  The path inside kmods is `prl_tg/Toolgate/Guest/Linux/prl_tg/` and we are focusing on the prltg.c file.

- PDE(ino)->data(); should be replaced with PDE_DATA(ino);

There is only one line with this, so you cannot possible mess it up.  AFAIK PDE->data is deprecated.

- `create_proc_entry` has been deprecated and replaced with `proc_create_data`.
    - Comment out the first line after the condition that follows
    - Add the fops component as the final argument to proc_create
    - The line below that comment out
    - Add `dev` to the final argument

To summarize, replace `p = create_proc_entry(proc_file, S_IWUGO, NULL)` with `p = proc_create_data(proc_file, S_IWUGO, NULL, board_info[dev->board].fops, dev)`, and comment out the two lines that previously accomplished the same (after the `if (p)`).


---

Our next concern is inside prl_fs (of course), and the problems are quite similar (same functions).

This patch was the file `super.c` inside `prl_fs/SharedFolders/Guest/Linux/prl_fs/`, and consisted of:

    //  p = create_proc_entry("sf_list", S_IFREG | S_IRUGO, proc_prlfs);
        p = proc_create("sf_list", S_IFREG | S_IRUGO, proc_prlfs, &proc_sf_operations);
        if (p == NULL) {
            remove_proc_entry("fs/prl_fs", NULL);
            ret = -ENOMEM;
            goto out;
        }
    //  p->proc_fops = &proc_sf_operations;

Fortunately that appears to be all we had to fix to get past that stage.


---

Next up is `prl_fs_freeze`, which has a number of errors.

The path `prl_fs_freeze/Snapshot/Guest/Linux/prl_freeze modules`, and the file `prl_fs_freeze.c`.

Despite the daunting size of the error output the solutions are easy.  First, kmalloc has been moved to slab.h, so add the include <linux/slab.h> fixes the majority of the problems.

The second is going back to the deprecated `create_proc_entry` method, and the change is:

    struct proc_dir_entry *entry;
    //  entry = create_proc_entry("driver/prl_freeze", S_IFREG|0664, NULL);
    entry = proc_create("driver/prl_freeze", S_IFREG|0664, NULL, &freeze_ops);
    if (!entry)
        return -ENOMEM;
    entry->proc_fops = &freeze_ops;


---

Following these modifications the build process was successful, so my next step was repackaging the changes in order to install them using the script (and distribute the patched copy).

We can do this by running (from inside the containing folder):

    tar -cf prl_mod.tar ./*
    gzip -c prl_mod.tar > prl_mod.tar.gz

Simply cp it over the original and run the `./install` from inside the original and you are all set.


### Known Bugs

There are some issues still with parallels tools after the patches are applied.

- Graphics are not fully enhanced
- Drag and drop between systems doesn't always work.
- The latest 3.11 kernel broke file sharing.
- The init.d script is outdated since Fedora uses systemd

It appears that the correct driver and vga device have loaded, but the vga's BDF pci path does not exist in the /sys directory, and further the screen does not automatically resize.

You can read more about the file system bug and systemd patches in the [issue](https://github.com/CDeLorme/fedora_parallels_tools/issues/1) posted by [denji](https://github.com/denji).

**This project is discontinued, the latest release of Parallels 9 addresses all these problems and works great.**
