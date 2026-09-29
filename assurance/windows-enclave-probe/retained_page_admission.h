/* QueryWorkingSetEx's Locked member is meaningful only for a Valid entry.
 * Pre-lock checks exclude another owner's lock; POST-lock admission requires
 * both valid and locked. This does not interpret invalid entries as residency. */
static int retained_page_accepts(unsigned valid, unsigned locked, unsigned required) {
    return required ? (valid && locked) : !(valid && locked);
}
