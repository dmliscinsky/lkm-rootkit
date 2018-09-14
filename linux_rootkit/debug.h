/*
 * Author: Daniel Liscinsky
 */


#ifndef KMODULE_DEBUG_H
#define KMODULE_DEBUG_H


//#define K_DEBUG

#ifdef K_DEBUG

#define DEBUG_pr_info(x) pr_info(x)
#define DEBUG_printk1(a)			printk(a)
#define DEBUG_printk2(a, b)			printk(a, b)
#define DEBUG_printk3(a, b, c)		printk(a, b, c)
#define DEBUG_printk4(a, b, c, d)	printk(a, b, c, d)

#else

#define DEBUG_pr_info(x) ;
#define pr_info(x) ;

#define DEBUG_printk1(a) ;
#define DEBUG_printk2(a, b)	;
#define DEBUG_printk3(a, b, c) ;
#define DEBUG_printk4(a, b, c, d) ;

#endif


#endif //KMODULE_DEBUG_H