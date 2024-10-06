package fileresolver

import (
	"fmt"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/internal/windows"
	"github.com/wagoodman/go-progress"
	"io/fs"
	"os"
	"path/filepath"
)

type fileIndexer struct {
	path              string
	base              string
	pathIndexVisitors []PathIndexVisitor
	errPaths          map[string]error
	tree              filetree.ReadWriter
	index             filetree.Index
}

func newFileIndexer(path, base string, visitors ...PathIndexVisitor) *fileIndexer {
	i := &fileIndexer{
		path:  path,
		base:  base,
		tree:  filetree.New(),
		index: filetree.NewIndex(),
		pathIndexVisitors: append(
			[]PathIndexVisitor{
				requireFileInfo,
				disallowByFileType,
				skipPathsByMountTypeAndName(path),
			},
			visitors...,
		),
		errPaths: make(map[string]error),
	}

	// these additional stateful visitors should be the first thing considered when walking / indexing
	/// TODO: I don't know if we need these yet...
	i.pathIndexVisitors = append(
		[]PathIndexVisitor{
			i.disallowRevisitingVisitor,
			i.disallowFileAccessErr,
		},
		i.pathIndexVisitors...,
	)

	return i
}

// Build the indexer
func (r *fileIndexer) build() (filetree.Reader, filetree.IndexReader, error) {
	return r.tree, r.index, index(r.path, r.indexPath)
}

// Index file at the given path
// A file indexer simply indexes the file and its directory.
func index(path string, indexer func(string, *progress.Stage) ([]string, error)) error {
	// We want to index the file at the provided path and its parent directory.
	// We need to probably check that we have file access
	// We also need to determine what to do when the file itself is a symlink.
	stager, prog := indexingProgress(path)
	defer prog.SetCompleted()

	// TODO: I don't think our indexer will ever return additionalRoots...
	// If we don't need it, then remoce it from the function signature of indexPath...
	_, err := indexer(path, stager)
	if err != nil {
		return fmt.Errorf("Unable to index filesystem path=%q: %w", path, err)
	}

	return nil

}

// This is where we actually do the indexing logic for the file
// path will be the path to file like "./a/b/c.txt"
// We will ensure we get the absolute symlink free path
func (r *fileIndexer) indexPath(path string, stager *progress.Stage) ([]string, error) {
	// TODO: Impl similar logic to indexTree in directory_indexer
	log.WithFields("path", path).Trace("indexing file path")

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// Protect against callers trying to call file_indexer with directories
	fi, err := os.Stat(absPath)
	// Directory indexing ignores stat errors, single file indexing shouldn't
	// because we aren't walking the filesystem here, we don't need to ignore & continue.
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", path, err)
	}

	if fi != nil {
		if fi.IsDir() {
			return nil, fmt.Errorf("unable to index file, given path was a directory=%q", path)
		}
	}

	// If we get here then we have a file. We will index it and its parent
	absSymlinkFreeFilePath, err := absoluteSymlinkFreePathToFile(path)
	if err != nil {
		return nil, err
	}

	stager.Current = absSymlinkFreeFilePath
	indexFileErr := r.filterAndIndex(absSymlinkFreeFilePath, fi)

	if indexFileErr != nil {
		// TODO: What to do if we error here? We could look at SkipDir,SkipFile errs in case filters are set up I guess??
	}

	// We've indexed the file, now index its parent
	absSymlinkFreeParent, err := absoluteSymlinkFreePathToParent(absSymlinkFreeFilePath)
	if err != nil {
		return nil, err
	}

	pfi, err := os.Stat(absSymlinkFreeParent)
	// TODO: Verify not an err here and not nil pfi before continue
	stager.Current = absSymlinkFreeParent
	indexParentErr := r.filterAndIndex(absSymlinkFreeParent, pfi)
	if indexParentErr != nil {
		// TODO: Again work out what behaviour here should be
	}

	// TODO: Remove first arg here don't think we need a return, just return nil err
	return nil, nil
}

func (r *fileIndexer) filterAndIndex(path string, info os.FileInfo) error {
	// check if any of the filters want us to ignore this path
	for _, filterFn := range r.pathIndexVisitors {
		if filterFn == nil {
			continue
		}

		if filterErr := filterFn(r.base, path, info, nil); filterErr != nil {
			// A filter function wants us to ignore this path, honour it
			return filterErr
		}
	}

	// here we check to see if we need to normalize paths to posix on the way in coming from windows
	if windows.HostRunningOnWindows() {
		path = windows.ToPosix(path)
	}

	err := r.addPathToIndex(path, info)
	// If we hit file access errors, isFileAccessErr will handle logging & adding
	// the path to the errPaths map.
	// While the directory_indexer does not let these cause the indexer to throw
	// we will here, as not having access to the file we index for a file source
	// probably makes the file source creation useless? I need to check with Syft owners.
	// This also poses the question, is errPaths worthless for file_indexer?
	if r.isFileAccessErr(path, err) {
		return err
	}

	return nil
}

// Add path to index. File indexer doesn't need to support symlink, as we should have abs symlink free path.
func (r *fileIndexer) addPathToIndex(path string, info os.FileInfo) error {
	switch t := file.TypeFromMode(info.Mode()); t {
	case file.TypeDirectory:
		return r.addDirectoryToIndex(path, info)
	case file.TypeRegular:
		return r.addFileToIndex(path, info)
	default:
		return fmt.Errorf("unsupported file type: %s", t)
	}
}

func (r *fileIndexer) addDirectoryToIndex(path string, info os.FileInfo) error {
	ref, err := r.tree.AddDir(file.Path(path))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(path, info)
	r.index.Add(*ref, metadata)

	return nil
}

func (r *fileIndexer) addFileToIndex(path string, info os.FileInfo) error {
	ref, err := r.tree.AddFile(file.Path(path))
	if err != nil {
		return err
	}

	metadata := file.NewMetadataFromPath(path, info)
	r.index.Add(*ref, metadata)

	return nil
}

// Get absolute symlink free path to parent of the file
func absoluteSymlinkFreePathToParent(path string) (string, error) {
	absFilePath, err := absoluteSymlinkFreePathToFile(path)
	if err != nil {
		return "", err
	}

	return filepath.Dir(absFilePath), nil
}

// Get absolute symlink free path to the file
func absoluteSymlinkFreePathToFile(path string) (string, error) {
	absAnalysisPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	dereferencedAbsAnalysisPath, err := filepath.EvalSymlinks(absAnalysisPath)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	return dereferencedAbsAnalysisPath, nil

}

// TODO: These are the same as directory_indexer funcs. Not sure we need them for files.
// TODO: Maybve want the disallowFileAccessErr functionality in some other way

func (r *fileIndexer) disallowRevisitingVisitor(_, path string, _ os.FileInfo, _ error) error {
	// this prevents visiting:
	// - link destinations twice, once for the real file and another through the virtual path
	// - infinite link cycles
	if indexed, metadata := r.hasBeenIndexed(path); indexed {
		if metadata.IsDir() {
			// signal to walk() that we should skip this directory entirely
			return fs.SkipDir
		}
		return ErrSkipPath
	}
	return nil
}

func (r *fileIndexer) disallowFileAccessErr(_, path string, _ os.FileInfo, err error) error {
	if r.isFileAccessErr(path, err) {
		return ErrSkipPath
	}
	return nil
}

func (r *fileIndexer) isFileAccessErr(path string, err error) bool {
	// don't allow for errors to stop indexing, keep track of the paths and continue.
	if err != nil {
		log.Warnf("unable to access path=%q: %+v", path, err)
		r.errPaths[path] = err
		return true
	}
	return false
}

func (r fileIndexer) hasBeenIndexed(p string) (bool, *file.Metadata) {
	filePath := file.Path(p)
	if !r.tree.HasPath(filePath) {
		return false, nil
	}

	exists, ref, err := r.tree.File(filePath)
	if err != nil || !exists || !ref.HasReference() {
		return false, nil
	}

	// cases like "/" will be in the tree, but not been indexed yet (a special case). We want to capture
	// these cases as new paths to index.
	if !ref.HasReference() {
		return false, nil
	}

	entry, err := r.index.Get(*ref.Reference)
	if err != nil {
		return false, nil
	}

	return true, &entry.Metadata
}
