"""
Master Reproducibility Script for Beacon Research Study.
Executes dataset extraction from frozen raw observations, aggregates summaries,
runs statistical analysis (Wilson CIs, Chi-Square, Kruskal-Wallis),
and verifies dataset integrity completely offline.
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.research_dataset import build_dataset, save_dataset, save_csv, summarize
from research.analyze_study import run_full_analysis


def reproduce():
    print("=" * 70)
    print("  BEACON RESEARCH STUDY: OFFLINE REPRODUCIBILITY PIPELINE")
    print("=" * 70)
    
    manifest = Path("research/pilot_manifest.csv")
    if not manifest.exists():
        manifest = Path("research/sampling/pilot_manifest.csv")
    if not manifest.exists():
        raise FileNotFoundError("Sampling manifest not found in research/ or research/sampling/")

    print(f"\n[1/3] Building research dataset from manifest ({manifest})...")
    dataset = build_dataset(manifest, target_root="data/targets", salt="beacon-study")
    
    # Save to primary and structured locations
    save_dataset(dataset, "research/dataset.json")
    save_csv(dataset, "research/dataset.csv")
    save_dataset(dataset, "research/dataset/dataset.json")
    save_csv(dataset, "research/dataset/dataset.csv")
    
    summary = summarize(dataset)
    Path("research/summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    Path("research/dataset/summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"      Successfully generated {len(dataset['observations'])} observations.")

    print("\n[2/3] Executing statistical analysis engine...")
    stats = run_full_analysis("research/dataset.json", "research/statistical_analysis.json")
    Path("research/statistics/statistical_analysis.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    
    print("\n[3/3] Research Results Summary:")
    print(f"      - Total Observations: {stats['study_metadata']['sample_size']}")
    print(f"      - SPF Adoption: {stats['prevalence']['spf']['count']}/{stats['study_metadata']['sample_size']} ({stats['prevalence']['spf']['proportion']*100:.1f}%) [95% CI: {stats['prevalence']['spf']['ci_95'][0]*100:.1f}% - {stats['prevalence']['spf']['ci_95'][1]*100:.1f}%]")
    print(f"      - DMARC Adoption: {stats['prevalence']['dmarc']['count']}/{stats['study_metadata']['sample_size']} ({stats['prevalence']['dmarc']['proportion']*100:.1f}%) [95% CI: {stats['prevalence']['dmarc']['ci_95'][0]*100:.1f}% - {stats['prevalence']['dmarc']['ci_95'][1]*100:.1f}%]")
    print(f"      - DMARC Enforced: {stats['prevalence']['dmarc']['enforced_count']}/{stats['study_metadata']['sample_size']} ({stats['prevalence']['dmarc']['enforced_proportion']*100:.1f}%)")
    print(f"      - Gov vs Non-Gov DMARC Chi-Square: Chi2 = {stats['statistical_tests']['government_vs_nongovernment_dmarc_adoption']['chi2']}, p = {stats['statistical_tests']['government_vs_nongovernment_dmarc_adoption']['p_value']}")
    
    print("\n" + "=" * 70)
    print("  REPRODUCIBILITY PIPELINE COMPLETED SUCCESSFULLY (100% OFFLINE)")
    print("=" * 70)


if __name__ == "__main__":
    reproduce()
