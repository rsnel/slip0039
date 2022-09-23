#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "dev.h"

int main(int argc, char *argv[]) {
	verbose_init(argv[0]);
	wordlists_init();
	const char *stuff;
	int ret;
	stuff = NULL;
	ret = wordeq("action mus", "act", &stuff, 1);
	printf("%d, ->%s<-\n", ret, stuff);
	stuff = NULL;
	ret = wordeq("act", "action", &stuff, 1);
	printf("%d, ->%s<-\n", ret, stuff);
	stuff = NULL;
	ret = wordeq("action mus", "action", &stuff, 1);
	printf("%d, ->%s<-\n", ret, stuff);
	stuff = NULL;
	ret = wordeq("abcde", "a", &stuff, 1);
	printf("%d, ->%s<-\n", ret, stuff);
	stuff = NULL;
	ret = wordeq("abcde", "a", &stuff, 0);
	printf("%d, ->%s<-\n", ret, stuff);
}
