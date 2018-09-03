class BidirectionalIterator(object):
    def __init__(self, collection):
        self.collection = collection
        self.index = -1 #starts on -1, as index is increased _before_ getting result
        self.step_back_once = False 

    def __next__(self):
        try:
            if self.step_back_once:
                self.index -= 1
                self.step_back_once = False 
                if self.index < 0:
                    raise StopIteration
            else:
                self.index += 1
            result = self.collection[self.index]
        except IndexError:
            raise StopIteration
        return result

    def step_back_on_next_iteration(self):
        self.step_back_once = True

    def can_step_back(self):
        return self.index > 0

    def __iter__(self):
        return self
