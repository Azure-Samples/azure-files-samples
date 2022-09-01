# Autoincrease Premium File Share Quota

## Overview
This method will create an Azure Function with a timer trigger that checks at a set interval (default 60min) to determine if it should auto-grow the file share.
The following options exist to AutoGrow by X% (Default 20%)
1. If 20% or less of its quota isn't free. Then the quota function will automatically increase the file share's quota by 20%
2. If File Share Level Throttling (IOPS or Bandwidth) is detected in the past 1 hour. Then the throttle function will automatically increase the file share's quota by 20%
## Setup Options
1. Use the ARM template.
2. Do all of this manually using the step-by-step guide.
## Function Options
1. Autogrow by Quota (see autoincrease PFS quota script)
1. Autogrow by Throttling (autoincrease PFS throttle script)
