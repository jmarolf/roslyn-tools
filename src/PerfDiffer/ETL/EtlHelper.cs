using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;

using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Stacks;

namespace PerfDiffer
{
    internal static class EtlHelper
    {
        public static TraceProcess GetTraceProcessFromETLFile(string eltPath)
        {
            var traceLog = TraceLog.OpenOrConvert(eltPath);
            return traceLog.Processes
                .Where(p => p.Name.Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                .First();
        }

        public static StackSource CreateStackSourceFromTraceProcess(TraceProcess process, string symbolPath)
        {
            var events = process.EventsInProcess;
            var start = Math.Max(events.StartTimeRelativeMSec, process.StartTimeRelativeMsec);
            var end = Math.Min(events.EndTimeRelativeMSec, process.EndTimeRelativeMsec);
            events = events.FilterByTime(start, end);
            events = events.Filter(x => x is SampledProfileTraceData && x.ProcessID == process.ProcessID);

            // Resolve symbols for clr and ntdll using the standard Microsoft symbol server path.
            using var symbolReader = new SymbolReader(new StringWriter(), @$"SRV*{symbolPath}");

            // By default the symbol reader will NOT read PDBs from 'unsafe' locations (like next to the EXE)
            // because hackers might make malicious PDBs.   If you wish ignore this threat, you can override this
            // check to always return 'true' for checking that a PDB is 'safe'.
            symbolReader.SecurityCheck = (path => true);

            var traceLog = process.Log;
            foreach (var module in process.LoadedModules)
            {
                traceLog.CodeAddresses.LookupSymbolsForModule(symbolReader, module.ModuleFile);
            }

            return new TraceEventStackSource(events);
        }

        public static CallTree CreateCallTreeFromStackSource(StackSource stackSource)
        {
            var calltree = new CallTree(ScalingPolicyKind.ScaleToData);
            calltree.StackSource = stackSource;
            return calltree;
        }

        public static ImmutableArray<OverWeightResult> GenerateOverweightReport(CallTree source, CallTree baseline)
        {
            var sourceTotal = LoadTrace(source, out var sourceData);
            var baselineTotal = LoadTrace(baseline, out var baselineData);

            if (sourceTotal != baselineTotal)
            {
                return ComputeOverweights(sourceTotal, sourceData, baselineTotal, baselineData);
            }

            return ImmutableArray<OverWeightResult>.Empty;

            static float LoadTrace(CallTree callTree, out Dictionary<string, float> data)
            {
                data = new Dictionary<string, float>();
                float total = 0;
                foreach (var node in callTree.ByID)
                {
                    if (node.InclusiveMetric == 0)
                    {
                        continue;
                    }

                    float weight = 0;

                    string key = node.Name;
                    data.TryGetValue(key, out weight);
                    data[key] = weight + node.InclusiveMetric;

                    total += node.ExclusiveMetric;
                }
                return total;
            }

            static ImmutableArray<OverWeightResult> ComputeOverweights(float sourceTotal, Dictionary<string, float> sourceData, float baselineTotal, Dictionary<string, float> baselineData)
            {
                var totalDelta = sourceTotal - baselineTotal;
                var growth = sourceTotal / baselineTotal;
                var results = ImmutableArray.CreateBuilder<OverWeightResult>();
                foreach (var key in baselineData.Keys)
                {
                    // skip symbols that are not in both traces
                    if (!sourceData.ContainsKey(key))
                    {
                        continue;
                    }

                    var baselineValue = baselineData[key];
                    var sourceValue = sourceData[key];
                    var expectedDelta = baselineValue * (growth - 1);
                    var delta = sourceValue - baselineValue;
                    var overweight = delta / expectedDelta * 100;
                    var percent = delta / totalDelta;
                    // Calculate interest level
                    var interest = Math.Abs(overweight) > 110 ? 1 : 0;
                    interest += Math.Abs(percent) > 5 ? 1 : 0;
                    interest += Math.Abs(percent) > 20 ? 1 : 0;
                    interest += Math.Abs(percent) > 100 ? 1 : 0;
                    interest += sourceValue / sourceTotal < 0.95 ? 1 : 0;  // Ignore top of the stack frames
                    interest += sourceValue / sourceTotal < 0.75 ? 1 : 0;  // Bonus point for being further down the stack.

                    results.Add(new OverWeightResult
                    (
                        Name: key,
                        Before: baselineValue,
                        After: sourceValue,
                        Delta: delta,
                        Overweight: overweight,
                        Percent: percent,
                        Interest: interest
                    ));
                }

                results.Sort((left, right) =>
                {
                    if (left.Interest < right.Interest)
                        return 1;

                    if (left.Interest > right.Interest)
                        return -1;

                    if (left.Overweight < right.Overweight)
                        return 1;

                    if (left.Overweight > right.Overweight)
                        return -1;

                    if (left.Delta < right.Delta)
                        return -1;

                    if (left.Delta > right.Delta)
                        return 1;

                    return 0;
                });

                return results.ToImmutable();
            }
        }
    }
}
