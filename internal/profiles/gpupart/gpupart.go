/*
 * Copyright The Kubernetes Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gpupart

import (
	"strconv"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/dra-example-driver/internal/profiles"
)

const ProfileName = "gpupart"

type Profile struct {
	profiles.NoopConfigHandler

	nodeName string
	numGPUs  int
}

func NewProfile(nodeName string, numGPUs int) Profile {
	return Profile{
		nodeName: nodeName,
		numGPUs:  numGPUs,
	}
}

// EnumerateDevices implements [profiles.Profile].
func (p Profile) EnumerateDevices() (resourceslice.DriverResources, error) {
	var devices []resourceapi.Device
	var counterSets []resourceapi.CounterSet

	quarterPart := resource.MustParse("20Gi")
	halfPart := quarterPart.DeepCopy()
	halfPart.Mul(2)
	whole := quarterPart.DeepCopy()
	whole.Mul(4)

	for i := range p.numGPUs {
		gpuName := "gpu-" + strconv.Itoa(i)
		counterSetName := gpuName + "-counter-set"

		// The whole GPU
		devices = append(devices, resourceapi.Device{
			Name: gpuName,
			Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
				"size": {
					StringValue: ptr.To("whole"),
				},
			},
			ConsumesCounters: []resourceapi.DeviceCounterConsumption{
				{
					CounterSet: counterSetName,
					Counters: map[string]resourceapi.Counter{
						"memory": {
							Value: whole,
						},
					},
				},
			},
		})
		counterSets = append(counterSets, resourceapi.CounterSet{
			Name: counterSetName,
			Counters: map[string]resourceapi.Counter{
				"memory": {
					Value: whole,
				},
			},
		})

		// The partitions

		// halves
		for j := range 2 {
			devices = append(
				devices,
				resourceapi.Device{
					Name: gpuName + "-part-half-" + strconv.Itoa(j),
					Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
						"size": {
							StringValue: ptr.To("half"),
						},
					},
					ConsumesCounters: []resourceapi.DeviceCounterConsumption{
						{
							CounterSet: counterSetName,
							Counters: map[string]resourceapi.Counter{
								"memory": {
									Value: halfPart,
								},
							},
						},
					},
				},
			)
		}

		// quarters
		for j := range 4 {
			devices = append(
				devices,
				resourceapi.Device{
					Name: gpuName + "-part-quarter-" + strconv.Itoa(j),
					Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
						"size": {
							StringValue: ptr.To("quarter"),
						},
					},
					ConsumesCounters: []resourceapi.DeviceCounterConsumption{
						{
							CounterSet: counterSetName,
							Counters: map[string]resourceapi.Counter{
								"memory": {
									Value: quarterPart,
								},
							},
						},
					},
				},
			)
		}
	}

	resources := resourceslice.DriverResources{
		Pools: map[string]resourceslice.Pool{
			p.nodeName: {
				Slices: []resourceslice.Slice{
					{
						SharedCounters: counterSets,
					},
					{
						Devices: devices,
					},
				},
			},
		},
	}

	return resources, nil
}
