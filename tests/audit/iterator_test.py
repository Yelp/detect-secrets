import pytest

from detect_secrets.audit.iterator import BidirectionalIterator


class TestBidirectionalIterator:

    def test_no_input(self):
        iterator = BidirectionalIterator([])
        with pytest.raises(StopIteration):
            iterator.__next__()

    def test_cannot_step_back_too_far(self):
        iterator = BidirectionalIterator([0])
        iterator.step_back_on_next_iteration()
        with pytest.raises(StopIteration):
            iterator.__next__()

    def test_cannot_step_back_too_far_after_stepping_in(self):
        iterator = BidirectionalIterator([0, 1, 2])
        for _ in range(3):
            iterator.__next__()
        for _ in range(2):
            iterator.step_back_on_next_iteration()
            iterator.__next__()
        iterator.step_back_on_next_iteration()
        with pytest.raises(StopIteration):
            iterator.__next__()

    def test_works_correctly_in_loop(self):
        iterator = BidirectionalIterator([0, 1, 2, 3, 4, 5])
        commands = [0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0]
        command_count = 0
        results = []
        for index in iterator:
            if commands[command_count]:
                iterator.step_back_on_next_iteration()
            results.append(index)
            command_count += 1
        assert results == [0, 1, 0, 1, 2, 1, 0, 1, 2, 3, 4, 3, 2, 3, 4, 5]

    def test_normal_iterator_if_not_told_to_step_back(self):
        input_list = [0, 1, 2, 3, 4, 5]
        iterator = BidirectionalIterator(input_list)
        results = []
        for index in iterator:
            results.append(index)
        assert results == input_list

    def test_knows_when_stepping_back_possible(self):
        iterator = BidirectionalIterator([0, 1, 2, 3])
        commands = [0, 1, 0, 0, 1, 1, 0, 0, 0, 0]
        command_count = 0
        results = []
        for _ in iterator:
            if commands[command_count]:
                iterator.step_back_on_next_iteration()
            results.append(iterator.can_step_back())
            command_count += 1
        assert results == [False, True, False, True, True, True, False, True, True, True]
