#include <unistd.h>

/* Assign *unit a unit string from table unit_label that best fits value.
 * returns the value reduced by the chosen unit's magnitude
 *
 * Tables are worked through in order, stopping at an entry with a falsey
 * label. While the value is larger than the current unit's maximum count,
 * the value is divided by this count and the next unit in the table is
 * examined. Example:
 *    100 flooby
 *    500 glargle
 *     30 lafplop     // Can be any count
 *       0 NULL       // Can be any count
 *
 * Given this table, a value of:
 *    150 will store glargle and return 1.5
 *     50 will store flooby  and return 50
 *  55000 will store lafplop and return 1.1
 */
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
