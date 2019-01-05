from .baseline import format_baseline_for_output


def write_baseline_to_file(filename, data):  # pragma: no cover
    with open(filename, 'w') as f:
        f.write(format_baseline_for_output(data) + '\n')
