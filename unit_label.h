struct unit_label {
	double lower_bound;
	char *label;
};

double make_unit_whatsit(const struct unit_label l[], char **unit, double value);
