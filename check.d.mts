type StringMap = Record<string, string>;
interface SourceLanguagePolicy {
    default: string;
    roots: string[];
    /** Roots that a build context such as a Docker image may omit entirely (tests, scripts); production roots stay required. */
    optionalRoots?: string[];
    legacyJavaScript: string[];
    generated: StringMap;
    artifactDirectories?: string[];
    testDirectories?: string[];
    nativeFiles?: StringMap;
    compilerProjects: string[];
}
export interface PackageManifest {
    name?: string;
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
export declare function checkRuntimeVersion(version?: unknown): string[];
export declare function checkVendoredFloors(directory: string, manifest: PackageManifest): string[];
export declare function checkManifest(manifest: PackageManifest): string[];
/** Optional roots absent from this checkout. Their ratchet runs where they exist (repository CI), not in build contexts. */
export declare function omittedRoots(directory: string, policy: SourceLanguagePolicy | undefined): string[];
export declare function inspectSourcePolicy(directory: string, policy: SourceLanguagePolicy, compilation: Compilation): string[];
export declare function checkSourceLanguage(directory: string, name: string): string[];
export declare function checkPresentation(directory: string, name: string, { parseAst }?: {
    parseAst?: ParseAst;
}): string[];
export declare function updatePresentationBaseline(directory: string, name: string, options?: {
    parseAst?: ParseAst;
}): string[];
export declare function collectReleaseIdentity(directory: string, { tag, commit, tagObject, archive, archiveSha256, event }?: ReleaseOptions): ReleaseEvidence;
export {};
