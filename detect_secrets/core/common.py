from .baseline import format_baseline_for_output


def write_baseline_to_file(filename, data):
    """
    :type filename: str
    :type data: dict
    :rtype: None
    """
    with open(filename, 'w') as f:  # pragma: no cover
        f.write(format_baseline_for_output(data) + '\n')
