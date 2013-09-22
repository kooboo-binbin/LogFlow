﻿using LogFlow.Specifications.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogFlow.Specifications.Flows
{
    public class FlowWithoutProcess: Flow
    {
        public FlowWithoutProcess()
        {
            CreateProcess("TestProcess", new TestInput());
        }
    }
}
