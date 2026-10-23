// Isolate application Tick sampling from network maintenance and notifications.
package comet

import "sync"

// sampleTicket identifies one sampling epoch; its address fences late results.
type sampleTicket struct{ marker byte }

// sampleJob owns a retained Beacon reference while queued or executing.
type sampleJob struct {
	beacon *Beacon       // Owner whose Wait must include actual callback completion.
	ticket *sampleTicket // Epoch captured at queue admission.
}

// sampler uses fixed workers and a bounded queue, initialized only on first Tick.
type sampler struct {
	jobs    chan sampleJob // At most 64 waiting samples for the entire Client.
	workers sync.WaitGroup // Actual worker completion, after all role jobs drain.
}

// sampleQueue obtains a shared sampler without starting application work under mu.
func (client *Client) sampleQueue() *sampler {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed.Load() {
		return nil
	}
	if client.sampling == nil {
		client.sampling = &sampler{jobs: make(chan sampleJob, 64)}
		client.sampling.workers.Add(2)
		for range 2 {
			go client.sampling.work()
		}
	}
	return client.sampling
}

// work executes only user sampling; Beacon renewal uses independent RPC slots.
func (queue *sampler) work() {
	defer queue.workers.Done()
	for job := range queue.jobs {
		job.beacon.sample(job.ticket)
		job.beacon.life.release()
	}
}

// close joins workers after all admitted jobs have returned their role tokens.
func (queue *sampler) close() {
	close(queue.jobs)
	queue.workers.Wait()
}
