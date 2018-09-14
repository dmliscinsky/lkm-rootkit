/*
 * Debugging for userland processes.
 * 
 * Author: Daniel Liscinsky
 */


#ifndef USERLAND_DEBUG_H
#define USERLAND_DEBUG_H


//#define U_DEBUG

#ifdef U_DEBUG

#define DEBUG_printf1(a)			printf(a)
#define DEBUG_printf2(a, b)			printf(a, b)
#define DEBUG_printf3(a, b, c)		printf(a, b, c)
#define DEBUG_printf4(a, b, c, d)	printf(a, b, c, d)

#else

#define DEBUG_printf1(a) ;
#define DEBUG_printf2(a, b)	;
#define DEBUG_printf3(a, b, c) ;
#define DEBUG_printf4(a, b, c, d) ;

#endif


#endif //USERLAND_DEBUG_H