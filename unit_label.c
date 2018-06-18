#include <unistd.h>

#include "unit_label.h"

/* Assign *unit a unit string from table unit_label that best fits value.
 * returns the value reduced by the chosen unit's magnitude
 *
 * Tables are worked through in order, stopping at an entry with a falsey
 * label. While the value is larger than the current unit's maximum count,
 * the value is divided by this count and the next unit in the table is
 * examined. Example:
 *    {100, "flooby" },
 *    {500, "glargle"},
 *    { 30, "lafplop"},  // Can be any non-zero count
 *    {  0, NULL     }   // Can be any count
 *
 * Given this table is in `labels`,
 *  ret1 = make_unit_whatsit(labels, &unit1, 150);
 *  ret2 = make_unit_whatsit(labels, &unit2, 50);
 *  ret3 = make_unit_whatsit(labels, &unit3, 55000);
 * leaves ret1 as 1.5 and unit1 as "gargle",
 * leaves ret2 as 50  and unit2 as "flooby",
 * leaves ret3 as 1.1 and unit3 as "lafplop",
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
