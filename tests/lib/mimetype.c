#include <libmonkey.h>

int main(void) {

	mklib_ctx c1 = mklib_init(NULL, 0, 0, NULL);
	if (!c1) return 1;

    char name1[] = "name1", name2[] = "name2";
    int size = 0, i = 0;

	if (!mklib_start(c1))
        return 1;

    struct mklib_mime **mts = mklib_mimetype_list(c1);

    while(mts[i++])
        size++;

    mklib_mimetype_add(c1, name1, "1");
    mklib_mimetype_add(c1, name2, "2");

    mts = mklib_mimetype_list(c1);
    i = 0;
    while (mts[i++])
        size--;

    if (size != -2)
        return 1;

	if (!mklib_stop(c1))
        return 1;

	return 0;
}
