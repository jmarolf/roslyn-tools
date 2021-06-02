namespace PerfDiffer
{
    record OverWeightResult(string Name, float Before, float After, float Delta, float Overweight, float Percent, int Interest)
    {
        public override string ToString()
            => $"'{Name}':, Overweight: '{Overweight}%', Before: '{Before}ms', After: '{After}ms', Interest :'{Interest}'";
    }
}
