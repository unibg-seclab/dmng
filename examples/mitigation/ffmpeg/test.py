#!/usr/bin/python3

import os
import subprocess
import sys
import unittest

ffmpeg = "./FFmpeg/ffmpeg"
landlock_service = "../landlock_service/target/release/landlock_service"
policy = "./policy.json"


class FFmpegTests(unittest.TestCase):

    capture_output = True

    def test_1_works_as_intended(self):
        print("\n==============")
        print("Normal input for FFmpeg")
        print("==============")
        t = subprocess.run([ffmpeg,
                            "-i",
                            "10.jpg",
                           "output/normal_output.png"],
                           stdout=subprocess.PIPE)
        self.assertTrue(t.returncode == 0)
        self.assertTrue(os.path.exists('output/normal_output.png'))
        os.remove('output/normal_output.png')

    def test_2_exploit(self):
        print("\n==============")
        print("Exploit for FFmpeg")
        print("==============")

        t = subprocess.run([ffmpeg,
                            "-i",
                            "file_read.avi",
                           "output/vulnerable_output.mp4"],
                           stdout=subprocess.PIPE)

        self.assertTrue(t.returncode == 0)
        self.assertTrue(os.path.exists('output/vulnerable_output.mp4'))
        os.remove('output/vulnerable_output.mp4')

    def test_3_landlock(self):
        print("\n==============")
        print("Exploit blocked by Landlock")
        print("==============")
        t = subprocess.run([landlock_service,
                            "--policy",
                            "policy.json",
                            '--command',
                            f"{ffmpeg} -i file_read.avi output/blocked.mp4"],
                           stdout=subprocess.PIPE)

        self.assertTrue(t.returncode == 0)
        self.assertTrue(not os.path.exists('output/blocked.mp4'))


if __name__ == "__main__":

    """
    Run the tests
    """
    if len(sys.argv) > 1:
        if sys.argv[1] == '-v' or sys.argv[1] == '--verbose':
            FFmpegTests.capture_output = False
    unittest.main(verbosity=2)
