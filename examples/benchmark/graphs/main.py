import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.size': 15,
    'pdf.fonttype': 42,
    'ps.fonttype': 42
})


CONVERT_SMALL_CSV = '../convert_small.csv'
CONVERT_MED_CSV = '../convert_med.csv'
CONVERT_LARGE_CSV = '../convert_large.csv'
FFMPEG_1_CSV = '../ffmpeg_a.csv'
FFMPEG_10_CSV = '../ffmpeg_b.csv'
FFMPEG_100_CSV = '../ffmpeg_c.csv'

TEST_LABELS = {
    'none': 'None',
    'landlock': 'Landlock',
    'ebpf': 'Landlock+eBPF'
}

CONVERT_LABELS = {
    'convert_id': 'Copy',
    'convert_enhance': 'Enhance',
    'convert_resize': 'Resize',
    'convert_sharpen': 'Sharpen',
    'convert_rotate': 'Rotate',
    'convert_swirl': 'Swirl',
}

FFMPEG_LABELS = {
    'ffmpeg_decode': 'Decode',
    'ffmpeg_copy': 'Copy',
    'ffmpeg_cut': 'Cut',
    'ffmpeg_loop': 'Loop',
    'ffmpeg_extract_audio': 'Extract Audio',
}


def percentage_diff(tpl):
    measure, base = tpl
    if measure == base:
        return ''
    diff = round(((measure / base) - 1) * 100, ndigits=1)
    if diff == 0:
        return '0%'
    return f'{diff}%'


def grouped_bar(x_labels, csv, output, color_cycle=["#1f77b4", "#ff7f03", "#2ca02c"]):
    df = pd.read_csv(csv)
    names = df['name'].unique().tolist()
    means = df.groupby(['name', 'test_type'])['time'].mean()
    test_type_means = {
        TEST_LABELS['none']: [means.loc[name, 'none'] for name in names],
        TEST_LABELS['landlock']: [means.loc[name, 'landlock'] for name in names],
        TEST_LABELS['ebpf']: [means.loc[name, 'ebpf'] for name in names],
    }

    x = np.arange(len(names))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0

    fig, ax = plt.subplots(layout='constrained')

    items = list(test_type_means.items())

    _, base = items[0]

    for color, (attribute, measurement) in zip(color_cycle, items):
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute, color=color)
        diffs = list(map(percentage_diff, zip(measurement, base)))
        ax.bar_label(rects, padding=3, labels=diffs, rotation=90, label_type='edge')
        multiplier += 1

    ax.set_ylabel('Time [ms]')
    ax.set_xticks(x + width, [x_labels[name] for name in names])
    ax.legend(bbox_to_anchor=(0, 1.02, 1, 0.2), ncol=3, mode="expand", loc="lower left", frameon=False)
    top = max([x for _, xs in items for x in xs])
    ax.set_ylim(0, top + top / 4)

    plt.savefig(output, bbox_inches='tight')


grouped_bar(CONVERT_LABELS, CONVERT_SMALL_CSV, 'convert_small.pdf')
grouped_bar(CONVERT_LABELS, CONVERT_MED_CSV, 'convert_med.pdf')
grouped_bar(CONVERT_LABELS, CONVERT_LARGE_CSV, 'convert_large.pdf')
grouped_bar(FFMPEG_LABELS, FFMPEG_1_CSV, 'ffmpeg_1.pdf', color_cycle=['orchid', 'teal', 'purple'])
grouped_bar(FFMPEG_LABELS, FFMPEG_10_CSV, 'ffmpeg_10.pdf', color_cycle=['orchid', 'teal', 'purple'])
grouped_bar(FFMPEG_LABELS, FFMPEG_100_CSV, 'ffmpeg_100.pdf', color_cycle=['orchid', 'teal', 'purple'])
