#!/usr/bin/python3

import os
import subprocess
import sys
import unittest

convert = "./ImageMagick-7.0.10-36/utilities/magick"
landlock_service = "../landlock_service/target/release/landlock_service"
policy = "./policy.json"


class ImageMagickTests(unittest.TestCase):

    capture_output = True

    def test_1_works_as_intended(self):
        print("\n==============")
        print("Normal input for ImageMagick")
        print("==============")
        t = subprocess.run([convert,
                            "./input_images/w3c.svg",
                           "output_images/normal_output.png"],
                           stdout=subprocess.PIPE)
        self.assertTrue(t.returncode == 0)

    def test_2_exploit(self):
        print("\n==============")
        print("Exploit for ImageMagick")
        print("==============")

        t = subprocess.run([convert,
                            "./input_images/poc_input.svg",
                           "output_images/vulnerable_output.png"],
                           stdout=subprocess.PIPE)

        self.assertTrue(t.returncode == -6)

        with open('exploited.txt', 'r') as f:
            print(f'Contents of exploited.txt:\n{f.read()}')
        os.remove('exploited.txt')

    def test_3_landlock(self):
        print("\n==============")
        print("Exploit blocked by Landlock")
        print("==============")
        t = subprocess.run([landlock_service,
                            "--policy",
                            "policy.json",
                            '--command',
                            f"{convert} ./input_images/policy_input.svg ./output_images/policy_output.png"],
                           stdout=subprocess.PIPE)

        self.assertTrue(t.returncode == 0)
        self.assertTrue(not os.path.exists('./should_not_appear.txt'))


if __name__ == "__main__":

    """
    Run the tests
    """
    if len(sys.argv) > 1:
        if sys.argv[1] == '-v' or sys.argv[1] == '--verbose':
            ImageMagickTests.capture_output = False
    unittest.main(verbosity=2)
