

```
.\GCP-PenTest-Enumerator.ps1                                    # Step 1: Enumerate
.\GCP-PenTest-Enumerator.ps1 -EnumDir .\GCP_PenTest_Output_* -Mode Aggressive
.\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_*        # Step 2: Safe test
.\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_* -Mode Aggressive  # Step 3: Full test
```
