# mass-AD-password-reset
PowerShell script that generates random AD-safe passwords, pulls usernames from input file, resets passwords, then outputs changes passwords to output file and console.

**Note:** This script is *not safe* for deployment in production Active Directory environments, as it outputs generated passwords in plain-text to both the console and an output file. This is only meant as a proof-of-concept.
