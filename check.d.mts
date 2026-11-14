type StringMap = Record<string, string>;
interface SourceLanguagePolicy {
    default: string;
    roots: string[];
    legacyJavaScript: string[];
    generated: StringMap;
    artifactDirectories?: string[];
    testDirectories?: string[];
    nativeFiles?: StringMap;
    compilerProjects: string[];
}
interface PresentationPolicy {
    roots: string[];
    baseline?: string;
    owner: string;
}
interface DataPolicy {
    roots: string[];
    baseline: string;
}
interface Profile {
    dependencies: StringMap;
    devDependencies: StringMap;
    sharedDependencies: string[];
    sharedDevDependencies: string[];
    peerDependencies: StringMap;
    checkScripts: string[];
    sourceLanguage?: SourceLanguagePolicy;
    presentation?: PresentationPolicy;
    data?: DataPolicy;
}
export interface PackageManifest {
    name?: string;
    packageManager?: string;
    type?: string;
    engines?: {
        node?: string;
    };
    dependencies?: StringMap;
    optionalDependencies?: StringMap;
    devDependencies?: StringMap;
    peerDependencies?: StringMap;
    scripts?: Record<string, string | undefined>;
    overrides?: unknown;
    resolutions?: unknown;
    pnpm?: {
        overrides?: unknown;
        patchedDependencies?: unknown;
        packageExtensions?: unknown;
    };
    bundledDependencies?: unknown;
    bundleDependencies?: unknown;
}
interface CompilerProject {
    compilerOptions?: Record<string, unknown>;
    files?: string[];
}
export interface Compilation extends CompilerProject {
    projects?: CompilerProject[];
    files: string[];
}
interface AstNode {
    type: string;
    [key: string]: any;
}
type ParseAst = (source: string, options: {
    lang: string;
}) => {
    body: AstNode[];
};
export interface ReleaseOptions {
    tag?: string;
    commit?: string;
    tagObject?: string;
    archive?: string;
    archiveSha256?: string;
    event?: string;
}
export interface ReleaseEvidence {
    name: string;
    version: string;
    tag: string;
    commit: string;
    tagObject: string;
    tagHistory: string;
    archive?: {
        filename: string;
        bytes: number;
        sha256: string;
        priorBytesVerified: boolean;
    };
}
export declare function inspectWaivers(): string[];
/** The profile a package name resolves to, with an app profile merged over the shared app stack. */
export declare function resolveProfile(packageName: string): {
    name: string;
    profile: Profile;
} | undefined;
export declare function checkRuntimeVersion(version?: unknown): string[];
export declare function checkVendoredFloors(directory: string, manifest: PackageManifest): string[];
export declare function checkManifest(manifest: PackageManifest): string[];
export declare function inspectSourcePolicy(directory: string, policy: SourceLanguagePolicy, compilation: Compilation): string[];
export declare function checkSourceLanguage(directory: string, name: string): string[];
export declare function checkPresentation(directory: string, name: string, { parseAst }?: {
    parseAst?: ParseAst;
}): string[];
export declare function updatePresentationBaseline(directory: string, name: string, options?: {
    parseAst?: ParseAst;
}): string[];
export declare function checkDeployment(directory: string, packageName: string): string[];
export declare function checkDataAccess(directory: string, packageName: string): string[];
export declare function updateRawStatementBaseline(directory: string, packageName: string): string[];
/**
 * Read-only: each consumer manifest against the current declaration. Nothing is installed, built or written. `status`
 * is manifest drift; `adoption` lists what the folder's container files and raw statements would still fail once
 * the consumer installs this release. Source-language and presentation checks need an install and are not run.
 */
export declare function driftReport(directories: string[]): {
    directory: string;
    name: string;
    status: 'current' | 'behind';
    runtime: string;
    problems: string[];
    adoption: string[];
}[];
export declare function collectReleaseIdentity(directory: string, { tag, commit, tagObject, archive, archiveSha256, event }?: ReleaseOptions): ReleaseEvidence;
export {};
