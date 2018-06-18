#include <unistd.h>

struct unit_label {
	/* number of times this unit fits into the immediate larger one */
	double count;

	/* label for the unit*/
	char *label;
};

double make_unit_whatsit(const struct unit_label l[], char **unit, double value) {
	size_t i = 0;

	for (i = 0; l[i+1].label; i++) {
		if (l[i].count > value) {
			break;
		}
		value /= l[i].count;
	}

	*unit = l[i].label;
	return value;
}
