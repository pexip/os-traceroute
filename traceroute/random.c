/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
					<dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/times.h>

#include "traceroute.h"


static void __init_random_seq (void) __attribute__ ((constructor));
static void __init_random_seq (void) {

	srand (times (NULL) + getpid ());
}


unsigned int random_seq (void) {

	/*  Not to worry about RANDOM_MAX and precision...  */
	return  (rand () << 16) ^ (rand () << 8) ^ rand () ^ (rand () >> 8);
}

