import pandas as pd
import sys


def to_agg_csv(csv):
    df = pd.read_csv(csv)
    df.groupby(['name', 'test_type']).agg({'time': ['mean', 'std']}).reset_index().to_csv(
        f'{csv.replace(".csv", "")}_agg.csv', index=False)


to_agg_csv(sys.argv[1])
