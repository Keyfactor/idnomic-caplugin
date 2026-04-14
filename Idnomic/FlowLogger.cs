/*
Copyright © 2025 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.Idnomic;

public enum FlowStepStatus { Success, Failed, Skipped, InProgress }

public class FlowStep
{
    public string Name { get; set; }
    public FlowStepStatus Status { get; set; }
    public string Detail { get; set; }
    public long ElapsedMs { get; set; }
    public List<FlowStep> Children { get; } = new();
}

public sealed class FlowLogger : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _flowName;
    private readonly Stopwatch _totalTimer;
    private readonly List<FlowStep> _steps = new();
    private FlowStep _currentParent;
    private bool _disposed;

    public FlowLogger(ILogger logger, string flowName)
    {
        _logger = logger;
        _flowName = flowName;
        _totalTimer = Stopwatch.StartNew();
        _logger.LogTrace("===== FLOW START: {FlowName} =====", _flowName);
    }

    public void Step(string name, string detail = null)
    {
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.Success,
            Detail = detail
        };
        AddStep(step);
    }

    public void Step(string name, Action action, string detail = null)
    {
        var sw = Stopwatch.StartNew();
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.InProgress,
            Detail = detail
        };
        AddStep(step);

        try
        {
            action();
            sw.Stop();
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Status = FlowStepStatus.Success;
        }
        catch
        {
            sw.Stop();
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Status = FlowStepStatus.Failed;
            throw;
        }
    }

    public async Task StepAsync(string name, Func<Task> action, string detail = null)
    {
        var sw = Stopwatch.StartNew();
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.InProgress,
            Detail = detail
        };
        AddStep(step);

        try
        {
            await action();
            sw.Stop();
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Status = FlowStepStatus.Success;
        }
        catch
        {
            sw.Stop();
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Status = FlowStepStatus.Failed;
            throw;
        }
    }

    public void Fail(string name, string reason = null)
    {
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.Failed,
            Detail = reason
        };
        AddStep(step);
    }

    public void Skip(string name, string reason = null)
    {
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.Skipped,
            Detail = reason
        };
        AddStep(step);
    }

    public void Branch(string name)
    {
        var step = new FlowStep
        {
            Name = name,
            Status = FlowStepStatus.InProgress
        };
        AddStep(step);
        _currentParent = step;
    }

    public void EndBranch()
    {
        _currentParent = null;
    }

    private void AddStep(FlowStep step)
    {
        if (_currentParent != null)
        {
            _currentParent.Children.Add(step);
        }
        else
        {
            _steps.Add(step);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _totalTimer.Stop();
        RenderFlow();
    }

    private void RenderFlow()
    {
        var sb = new StringBuilder();
        var overallStatus = DetermineOverallStatus();

        sb.AppendLine();
        sb.AppendLine($"  ===== FLOW: {_flowName} ({_totalTimer.ElapsedMilliseconds}ms total) =====");
        sb.AppendLine();

        for (int i = 0; i < _steps.Count; i++)
        {
            RenderStep(sb, _steps[i], "    ");

            if (i < _steps.Count - 1)
            {
                sb.AppendLine("    |");
                sb.AppendLine("    v");
            }
        }

        sb.AppendLine();
        sb.AppendLine($"  ===== FLOW RESULT: {overallStatus} =====");

        _logger.LogTrace(sb.ToString());
    }

    private void RenderStep(StringBuilder sb, FlowStep step, string indent)
    {
        var icon = step.Status switch
        {
            FlowStepStatus.Success => "[OK]",
            FlowStepStatus.Failed => "[FAIL]",
            FlowStepStatus.Skipped => "[SKIP]",
            FlowStepStatus.InProgress => "[...]",
            _ => "[?]"
        };

        var timing = step.ElapsedMs > 0 ? $" ({step.ElapsedMs}ms)" : "";
        var detail = !string.IsNullOrEmpty(step.Detail) ? $" [{step.Detail}]" : "";

        sb.AppendLine($"{indent}{icon} {step.Name}{timing}{detail}");

        foreach (var child in step.Children)
        {
            RenderStep(sb, child, indent + "  ");
        }
    }

    private string DetermineOverallStatus()
    {
        foreach (var step in _steps)
        {
            if (step.Status == FlowStepStatus.Failed || HasFailedChild(step))
                return "FAILED";
        }
        return "SUCCESS";
    }

    private bool HasFailedChild(FlowStep step)
    {
        foreach (var child in step.Children)
        {
            if (child.Status == FlowStepStatus.Failed || HasFailedChild(child))
                return true;
        }
        return false;
    }
}
