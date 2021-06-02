using System;
using System.Linq;

namespace PerfDiffer
{
    partial class Program
    {
        static void Main(string[] args)
        {
            var sourceEtlPath = args[0];
            var baselineEtlPath = args[1];
            var symbolLookupPath = args[2];
            var sourceProcess = EtlHelper.GetTraceProcessFromETLFile(sourceEtlPath);
            var baselineProcess = EtlHelper.GetTraceProcessFromETLFile(baselineEtlPath);
            var sourceStack = EtlHelper.CreateStackSourceFromTraceProcess(sourceProcess, symbolLookupPath);
            var sourceCallTree = EtlHelper.CreateCallTreeFromStackSource(sourceStack);
            var baselineStack = EtlHelper.CreateStackSourceFromTraceProcess(baselineProcess, symbolLookupPath);
            var baselineCallTree = EtlHelper.CreateCallTreeFromStackSource(baselineStack);

            var report = EtlHelper.GenerateOverweightReport(sourceCallTree, baselineCallTree);
            Console.WriteLine(string.Join(Environment.NewLine, report.Take(10)));
            // TODO: Filter out symbols not from code-under-test
        }
    }
}
