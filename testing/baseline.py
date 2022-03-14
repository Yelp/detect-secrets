baseline = {
    'generated_at': 'some timestamp',
    'plugins_used': [
        {
            'name': 'TestPlugin',
        },
    ],
    'results': {
        'filenameA': [
            {
                'hashed_secret': 'a',
                'line_number': 122,
                'type': 'Test Type',
            },
            {
                'hashed_secret': 'b',
                'line_number': 123,
                'type': 'Test Type',
            },
        ],
        'filenameB': [
            {
                'hashed_secret': 'c',
                'line_number': 123,
                'type': 'Test Type',
            },
        ],
    },
}

baseline_filename = 'will_be_mocked'
