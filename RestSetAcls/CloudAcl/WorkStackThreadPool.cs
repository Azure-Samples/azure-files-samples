using System;
using System.Collections.Generic;
using System.Threading;

namespace CloudAcl
{
    internal class WorkStackThreadPool<WorkItem>
    {
        private readonly Stack<WorkItem> stack = new Stack<WorkItem>();
        private readonly object stackLock = new object();
        private readonly ManualResetEvent doneEvent = new ManualResetEvent(false);
        private int activeWorkers = 0;

        private readonly int workerCount;
        private readonly Func<WorkItem, IEnumerable<WorkItem>> process;

        public WorkStackThreadPool(
            int workerCount,
            WorkItem initialWorkItem,
            Func<WorkItem, IEnumerable<WorkItem>> process)
        {
            stack.Push(initialWorkItem);
            this.workerCount = workerCount;
            this.process = process;
        }

        public void Start()
        {
            for (int i = 0; i < workerCount; i++)
            {
                var thread = new Thread(Worker);
                thread.Start();
            }
        }

        public void AwaitCompletion()
        {
            doneEvent.WaitOne();
        }

        private void Worker()
        {
            while (true)
            {
                WorkItem workItem = default;
                lock (stackLock)
                {
                    if (stack.Count > 0)
                    {
                        // If there is work to do, pop!
                        workItem = stack.Pop();
                        Interlocked.Increment(ref activeWorkers);
                    }
                    else
                    {
                        if (activeWorkers > 0)
                        {
                            // If there is currently no work, but there is another worker active, we may have work in the future,
                            // added by that active worker. So sleep a little, and try again later.
                            Thread.Sleep(10);
                            continue;
                        }
                        else
                        {
                            // If there is no work, and also no one else active, then we're done.
                            doneEvent.Set();
                            return;
                        }
                    }
                }

                try
                {
                    var newItems = process(workItem);
                    lock (stackLock)
                    {
                        foreach (var newItem in newItems)
                        {
                            stack.Push(newItem);
                        }
                    }
                }
                finally
                {
                    Interlocked.Decrement(ref activeWorkers);
                }
            }
        }
    }
}
