#include <unistd.h>

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
