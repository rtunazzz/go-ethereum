// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build !js && !wasip1
// +build !js,!wasip1

// Package leveldb implements the key-value database layer based on LevelDB.
package leveldb

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	// degradationWarnInterval specifies how often warning should be printed if the
	// leveldb database cannot keep up with requested writes.
	degradationWarnInterval = time.Minute

	// minCache is the minimum amount of memory in megabytes to allocate to leveldb
	// read and write caching, split half and half.
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	minHandles = 16

	// metricsGatheringInterval specifies the interval to retrieve leveldb database
	// compaction, io and pause stats to report to the user.
	metricsGatheringInterval = 3 * time.Second
)

// Database is a persistent key-value store. Apart from basic data storage
// functionality it also supports batch writes and iterating over the keyspace in
// binary-alphabetical order.
type Database struct {
	fn string      // filename for reporting
	db *leveldb.DB // LevelDB instance

	compTimeMeter       *metrics.Meter // Meter for measuring the total time spent in database compaction
	compReadMeter       *metrics.Meter // Meter for measuring the data read during compaction
	compWriteMeter      *metrics.Meter // Meter for measuring the data written during compaction
	writeDelayNMeter    *metrics.Meter // Meter for measuring the write delay number due to database compaction
	writeDelayMeter     *metrics.Meter // Meter for measuring the write delay duration due to database compaction
	diskSizeGauge       *metrics.Gauge // Gauge for tracking the size of all the levels in the database
	diskReadMeter       *metrics.Meter // Meter for measuring the effective amount of data read
	diskWriteMeter      *metrics.Meter // Meter for measuring the effective amount of data written
	memCompGauge        *metrics.Gauge // Gauge for tracking the number of memory compaction
	level0CompGauge     *metrics.Gauge // Gauge for tracking the number of table compaction in level0
	nonlevel0CompGauge  *metrics.Gauge // Gauge for tracking the number of table compaction in non0 level
	seekCompGauge       *metrics.Gauge // Gauge for tracking the number of table compaction caused by read opt
	manualMemAllocGauge *metrics.Gauge // Gauge to track the amount of memory that has been manually allocated (not a part of runtime/GC)

	levelsGauge []*metrics.Gauge // Gauge for tracking the number of tables in levels

	quitLock sync.Mutex      // Mutex protecting the quit channel access
	quitChan chan chan error // Quit channel to stop the metrics collection before closing the database

	log log.Logger // Contextual logger tracking the database path
}

// New returns a wrapped LevelDB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
func New(file string, cache int, handles int, namespace string, readonly bool) (*Database, error) {
	return NewCustom(file, namespace, func(options *opt.Options) {
		// Ensure we have some minimal caching and file guarantees
		if cache < minCache {
			cache = minCache
		}
		if handles < minHandles {
			handles = minHandles
		}
		// Set default options
		options.OpenFilesCacheCapacity = handles
		options.BlockCacheCapacity = cache / 2 * opt.MiB
		options.WriteBuffer = cache / 4 * opt.MiB // Two of these are used internally
		if readonly {
			options.ReadOnly = true
		}
	})
}

// NewCustom returns a wrapped LevelDB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
// The customize function allows the caller to modify the leveldb options.
func NewCustom(file string, namespace string, customize func(options *opt.Options)) (*Database, error) {
	options := configureOptions(customize)
	logger := log.New("database", file)
	usedCache := options.GetBlockCacheCapacity() + options.GetWriteBuffer()*2
	logCtx := []interface{}{"cache", common.StorageSize(usedCache), "handles", options.GetOpenFilesCacheCapacity()}
	if options.ReadOnly {
		logCtx = append(logCtx, "readonly", "true")
	}
	logger.Info("Allocated cache and file handles", logCtx...)

	// Open the db and recover any potential corruptions
	db, err := leveldb.OpenFile(file, options)
	if _, corrupted := err.(*lerrors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil)
	}
	if err != nil {
		return nil, err
	}
	// Assemble the wrapper with all the registered metrics
	ldb := &Database{
		fn:       file,
		db:       db,
		log:      logger,
		quitChan: make(chan chan error),
	}
	ldb.compTimeMeter = metrics.NewRegisteredMeter(namespace+"compact/time", nil)
	ldb.compReadMeter = metrics.NewRegisteredMeter(namespace+"compact/input", nil)
	ldb.compWriteMeter = metrics.NewRegisteredMeter(namespace+"compact/output", nil)
	ldb.diskSizeGauge = metrics.NewRegisteredGauge(namespace+"disk/size", nil)
	ldb.diskReadMeter = metrics.NewRegisteredMeter(namespace+"disk/read", nil)
	ldb.diskWriteMeter = metrics.NewRegisteredMeter(namespace+"disk/write", nil)
	ldb.writeDelayMeter = metrics.NewRegisteredMeter(namespace+"compact/writedelay/duration", nil)
	ldb.writeDelayNMeter = metrics.NewRegisteredMeter(namespace+"compact/writedelay/counter", nil)
	ldb.memCompGauge = metrics.NewRegisteredGauge(namespace+"compact/memory", nil)
	ldb.level0CompGauge = metrics.NewRegisteredGauge(namespace+"compact/level0", nil)
	ldb.nonlevel0CompGauge = metrics.NewRegisteredGauge(namespace+"compact/nonlevel0", nil)
	ldb.seekCompGauge = metrics.NewRegisteredGauge(namespace+"compact/seek", nil)
	ldb.manualMemAllocGauge = metrics.NewRegisteredGauge(namespace+"memory/manualalloc", nil)

	// Start up the metrics gathering and return
	go ldb.meter(metricsGatheringInterval, namespace)
	return ldb, nil
}

// configureOptions sets some default options, then runs the provided setter.
func configureOptions(customizeFn func(*opt.Options)) *opt.Options {
	// Set default options
	options := &opt.Options{
		Filter:                 filter.NewBloomFilter(10),
		DisableSeeksCompaction: true,
	}
	// Allow caller to make custom modifications to the options
	if customizeFn != nil {
		customizeFn(options)
	}
	return options
}

// Close stops the metrics collection, flushes any pending data to disk and closes
// all io accesses to the underlying key-value store.
func (db *Database) Close() error {
	db.quitLock.Lock()
	defer db.quitLock.Unlock()

	if db.quitChan != nil {
		errc := make(chan error)
		db.quitChan <- errc
		if err := <-errc; err != nil {
			db.log.Error("Metrics collection failed", "err", err)
		}
		db.quitChan = nil
	}
	return db.db.Close()
}

// Has retrieves if a key is present in the key-value store.
func (db *Database) Has(key []byte) (bool, error) {
	return db.db.Has(key, nil)
}

// Get retrieves the given key if it's present in the key-value store.
func (db *Database) Get(key []byte) ([]byte, error) {
	dat, err := db.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

// Put inserts the given value into the key-value store.
func (db *Database) Put(key []byte, value []byte) error {
	return db.db.Put(key, value, nil)
}

// Delete removes the key from the key-value store.
func (db *Database) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
// Note that this is a fallback implementation as leveldb does not natively
// support range deletion. It can be slow and therefore the number of deleted
// keys is limited in order to avoid blocking for a very long time.
// ErrTooManyKeys is returned if the range has only been partially deleted.
// In this case the caller can repeat the call until it finally succeeds.
func (db *Database) DeleteRange(start, end []byte) error {
	batch := db.NewBatch()
	it := db.NewIterator(nil, start)
	defer it.Release()

	var count int
	for it.Next() && (end == nil || bytes.Compare(end, it.Key()) > 0) {
		count++
		if count > 10000 { // should not block for more than a second
			if err := batch.Write(); err != nil {
				return err
			}
			return ethdb.ErrTooManyKeys
		}
		if err := batch.Delete(it.Key()); err != nil {
			return err
		}
	}
	return batch.Write()
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
func (db *Database) NewBatch() ethdb.Batch {
	return &batch{
		db: db.db,
		b:  new(leveldb.Batch),
	}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
func (db *Database) NewBatchWithSize(size int) ethdb.Batch {
	return &batch{
		db: db.db,
		b:  leveldb.MakeBatch(size),
	}
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
func (db *Database) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	return db.db.NewIterator(bytesPrefixRange(prefix, start), nil)
}

// Stat returns the statistic data of the database.
func (db *Database) Stat() (string, error) {
	var stats leveldb.DBStats
	if err := db.db.Stats(&stats); err != nil {
		return "", err
	}
	var (
		message       string
		totalRead     int64
		totalWrite    int64
		totalSize     int64
		totalTables   int
		totalDuration time.Duration
	)
	if len(stats.LevelSizes) > 0 {
		message += " Level |   Tables   |    Size(MB)   |    Time(sec)  |    Read(MB)   |   Write(MB)\n" +
			"-------+------------+---------------+---------------+---------------+---------------\n"
		for level, size := range stats.LevelSizes {
			read := stats.LevelRead[level]
			write := stats.LevelWrite[level]
			duration := stats.LevelDurations[level]
			tables := stats.LevelTablesCounts[level]

			if tables == 0 && duration == 0 {
				continue
			}
			totalTables += tables
			totalSize += size
			totalRead += read
			totalWrite += write
			totalDuration += duration
			message += fmt.Sprintf(" %3d   | %10d | %13.5f | %13.5f | %13.5f | %13.5f\n",
				level, tables, float64(size)/1048576.0, duration.Seconds(),
				float64(read)/1048576.0, float64(write)/1048576.0)
		}
		message += "-------+------------+---------------+---------------+---------------+---------------\n"
		message += fmt.Sprintf(" Total | %10d | %13.5f | %13.5f | %13.5f | %13.5f\n",
			totalTables, float64(totalSize)/1048576.0, totalDuration.Seconds(),
			float64(totalRead)/1048576.0, float64(totalWrite)/1048576.0)
		message += "-------+------------+---------------+---------------+---------------+---------------\n\n"
	}
	message += fmt.Sprintf("Read(MB):%.5f Write(MB):%.5f\n", float64(stats.IORead)/1048576.0, float64(stats.IOWrite)/1048576.0)
	message += fmt.Sprintf("BlockCache(MB):%.5f FileCache:%d\n", float64(stats.BlockCacheSize)/1048576.0, stats.OpenedTablesCount)
	message += fmt.Sprintf("MemoryCompaction:%d Level0Compaction:%d NonLevel0Compaction:%d SeekCompaction:%d\n", stats.MemComp, stats.Level0Comp, stats.NonLevel0Comp, stats.SeekComp)
	message += fmt.Sprintf("WriteDelayCount:%d WriteDelayDuration:%s Paused:%t\n", stats.WriteDelayCount, common.PrettyDuration(stats.WriteDelayDuration), stats.WritePaused)
	message += fmt.Sprintf("Snapshots:%d Iterators:%d\n", stats.AliveSnapshots, stats.AliveIterators)
	return message, nil
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
func (db *Database) Compact(start []byte, limit []byte) error {
	return db.db.CompactRange(util.Range{Start: start, Limit: limit})
}

// Path returns the path to the database directory.
func (db *Database) Path() string {
	return db.fn
}

// SyncKeyValue flushes all pending writes in the write-ahead-log to disk,
// ensuring data durability up to that point.
func (db *Database) SyncKeyValue() error {
	// In theory, the WAL (Write-Ahead Log) can be explicitly synchronized using
	// a write operation with SYNC=true. However, there is no dedicated key reserved
	// for this purpose, and even a nil key (key=nil) is considered a valid
	// database entry.
	//
	// In LevelDB, writes are blocked until the data is written to the WAL, meaning
	// recent writes won't be lost unless a power failure or system crash occurs.
	// Additionally, LevelDB is no longer the default database engine and is likely
	// only used by hash-mode archive nodes. Given this, the durability guarantees
	// without explicit sync are acceptable in the context of LevelDB.
	return nil
}

// meter periodically retrieves internal leveldb counters and reports them to
// the metrics subsystem.
func (db *Database) meter(refresh time.Duration, namespace string) {
	// Create the counters to store current and previous compaction values
	compactions := make([][]int64, 2)
	for i := 0; i < 2; i++ {
		compactions[i] = make([]int64, 4)
	}
	// Create storages for states and warning log tracer.
	var (
		errc chan error
		merr error

		stats           leveldb.DBStats
		iostats         [2]int64
		delaystats      [2]int64
		lastWritePaused time.Time
	)
	timer := time.NewTimer(refresh)
	defer timer.Stop()

	// Iterate ad infinitum and collect the stats
	for i := 1; errc == nil && merr == nil; i++ {
		// Retrieve the database stats
		// Stats method resets buffers inside therefore it's okay to just pass the struct.
		err := db.db.Stats(&stats)
		if err != nil {
			db.log.Error("Failed to read database stats", "err", err)
			merr = err
			continue
		}
		// Iterate over all the leveldbTable rows, and accumulate the entries
		for j := 0; j < len(compactions[i%2]); j++ {
			compactions[i%2][j] = 0
		}
		compactions[i%2][0] = stats.LevelSizes.Sum()
		for _, t := range stats.LevelDurations {
			compactions[i%2][1] += t.Nanoseconds()
		}
		compactions[i%2][2] = stats.LevelRead.Sum()
		compactions[i%2][3] = stats.LevelWrite.Sum()
		// Update all the requested meters
		db.diskSizeGauge.Update(compactions[i%2][0])
		db.compTimeMeter.Mark(compactions[i%2][1] - compactions[(i-1)%2][1])
		db.compReadMeter.Mark(compactions[i%2][2] - compactions[(i-1)%2][2])
		db.compWriteMeter.Mark(compactions[i%2][3] - compactions[(i-1)%2][3])
		var (
			delayN   = int64(stats.WriteDelayCount)
			duration = stats.WriteDelayDuration
			paused   = stats.WritePaused
		)
		db.writeDelayNMeter.Mark(delayN - delaystats[0])
		db.writeDelayMeter.Mark(duration.Nanoseconds() - delaystats[1])
		// If a warning that db is performing compaction has been displayed, any subsequent
		// warnings will be withheld for one minute not to overwhelm the user.
		if paused && delayN-delaystats[0] == 0 && duration.Nanoseconds()-delaystats[1] == 0 &&
			time.Now().After(lastWritePaused.Add(degradationWarnInterval)) {
			db.log.Warn("Database compacting, degraded performance")
			lastWritePaused = time.Now()
		}
		delaystats[0], delaystats[1] = delayN, duration.Nanoseconds()

		var (
			nRead  = int64(stats.IORead)
			nWrite = int64(stats.IOWrite)
		)
		db.diskReadMeter.Mark(nRead - iostats[0])
		db.diskWriteMeter.Mark(nWrite - iostats[1])
		iostats[0], iostats[1] = nRead, nWrite

		db.memCompGauge.Update(int64(stats.MemComp))
		db.level0CompGauge.Update(int64(stats.Level0Comp))
		db.nonlevel0CompGauge.Update(int64(stats.NonLevel0Comp))
		db.seekCompGauge.Update(int64(stats.SeekComp))

		for i, tables := range stats.LevelTablesCounts {
			// Append metrics for additional layers
			if i >= len(db.levelsGauge) {
				db.levelsGauge = append(db.levelsGauge, metrics.NewRegisteredGauge(namespace+fmt.Sprintf("tables/level%v", i), nil))
			}
			db.levelsGauge[i].Update(int64(tables))
		}

		// Sleep a bit, then repeat the stats collection
		select {
		case errc = <-db.quitChan:
			// Quit requesting, stop hammering the database
		case <-timer.C:
			timer.Reset(refresh)
			// Timeout, gather a new set of stats
		}
	}

	if errc == nil {
		errc = <-db.quitChan
	}
	errc <- merr
}

// batch is a write-only leveldb batch that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
type batch struct {
	db   *leveldb.DB
	b    *leveldb.Batch
	size int
}

// Put inserts the given value into the batch for later committing.
func (b *batch) Put(key, value []byte) error {
	b.b.Put(key, value)
	b.size += len(key) + len(value)
	return nil
}

// Delete inserts the key removal into the batch for later committing.
func (b *batch) Delete(key []byte) error {
	b.b.Delete(key)
	b.size += len(key)
	return nil
}

// DeleteRange removes all keys in the range [start, end) from the batch for
// later committing, inclusive on start, exclusive on end.
//
// Note that this is a fallback implementation as leveldb does not natively
// support range deletion in batches. It iterates through the database to find
// keys in the range and adds them to the batch for deletion.
func (b *batch) DeleteRange(start, end []byte) error {
	// Create an iterator to scan through the keys in the range
	slice := &util.Range{
		Start: start, // If nil, it represents the key before all keys
		Limit: end,   // If nil, it represents the key after all keys
	}
	it := b.db.NewIterator(slice, nil)
	defer it.Release()

	var count int
	for it.Next() {
		count++
		key := it.Key()
		if count > 10000 { // should not block for more than a second
			return ethdb.ErrTooManyKeys
		}
		// Add this key to the batch for deletion
		b.b.Delete(key)
		b.size += len(key)
	}
	if err := it.Error(); err != nil {
		return err
	}
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *batch) ValueSize() int {
	return b.size
}

// Write flushes any accumulated data to disk.
func (b *batch) Write() error {
	return b.db.Write(b.b, nil)
}

// Reset resets the batch for reuse.
func (b *batch) Reset() {
	b.b.Reset()
	b.size = 0
}

// Replay replays the batch contents.
func (b *batch) Replay(w ethdb.KeyValueWriter) error {
	return b.b.Replay(&replayer{writer: w})
}

// replayer is a small wrapper to implement the correct replay methods.
type replayer struct {
	writer  ethdb.KeyValueWriter
	failure error
}

// Put inserts the given value into the key-value data store.
func (r *replayer) Put(key, value []byte) {
	// If the replay already failed, stop executing ops
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Put(key, value)
}

// Delete removes the key from the key-value data store.
func (r *replayer) Delete(key []byte) {
	// If the replay already failed, stop executing ops
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Delete(key)
}

// DeleteRange removes all keys in the range [start, end) from the key-value data store.
func (r *replayer) DeleteRange(start, end []byte) {
	// If the replay already failed, stop executing ops
	if r.failure != nil {
		return
	}
	// Check if the writer also supports range deletion
	if rangeDeleter, ok := r.writer.(ethdb.KeyValueRangeDeleter); ok {
		r.failure = rangeDeleter.DeleteRange(start, end)
	} else {
		r.failure = errors.New("ethdb.KeyValueWriter does not implement DeleteRange")
	}
}

// bytesPrefixRange returns key range that satisfy
// - the given prefix, and
// - the given seek position
func bytesPrefixRange(prefix, start []byte) *util.Range {
	r := util.BytesPrefix(prefix)
	r.Start = append(r.Start, start...)
	return r
}
