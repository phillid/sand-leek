struct unit_label {
	/* number of times this unit fits into the immediate larger one */
	double count;

	/* label for the unit*/
	char *label;
};

double make_unit_whatsit(const struct unit_label l[], char **unit, double value);
